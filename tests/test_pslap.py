import dataclasses

import pytest

from qsv2v.attacks.common import AuthenticationError, SimClock
from qsv2v.attacks.pslap import attacks as A
from qsv2v.attacks.pslap import protocol as P
from qsv2v.crypto import DeterministicRNG


@pytest.fixture
def env():
    rng = DeterministicRNG(21)
    clock = SimClock()
    ta = P.setup(rng)
    drone = P.register_drone(rng)
    av = P.register_vehicle(ta, rng, b"hunter42", clock)
    return rng, clock, ta, drone, av


# -- protocol as printed ----------------------------------------------------
@pytest.mark.parametrize("variant", ["text", "figure"])
def test_honest_handshake(env, variant):
    rng, clock, ta, drone, av = env
    s = P.handshake(av, drone, ta, clock, rng, variant)
    assert len(s.sk) == 32


def test_text_variant_sends_static_pid(env):
    rng, clock, ta, drone, av = env
    s1 = P.handshake(av, drone, ta, clock, rng, "text")
    s2 = P.handshake(av, drone, ta, clock, rng, "text")
    assert s1.msg1.ident == s2.msg1.ident == av.PID


def test_figure_variant_masks_pid(env):
    rng, clock, ta, drone, av = env
    s1 = P.handshake(av, drone, ta, clock, rng, "figure")
    s2 = P.handshake(av, drone, ta, clock, rng, "figure")
    assert s1.msg1.ident != s2.msg1.ident and av.PID not in (s1.msg1.ident, s2.msg1.ident)


def test_login(env):
    *_, av = env
    assert P.login(av.ID, b"hunter42", av.obu) == (av.a1, av.alpha, av.PID)
    with pytest.raises(AuthenticationError):
        P.login(av.ID, b"wrong", av.obu)


def test_printed_login_check_always_fails(env):
    """Registration hashes beta into delta; the printed login check uses gamma."""
    *_, av = env
    with pytest.raises(AuthenticationError):
        P.login(av.ID, b"hunter42", av.obu, as_printed=True)


def test_tampered_messages_rejected(env):
    rng, clock, ta, drone, av = env
    m1, st = P.av_initiate(av, drone.ID, drone.Pu, clock, rng)
    with pytest.raises(AuthenticationError):
        P.drone_respond(drone, dataclasses.replace(m1, m2=b"\x00" * 32), ta.database, clock, rng)
    m2, _, _ = P.drone_respond(drone, m1, ta.database, clock, rng)
    with pytest.raises(AuthenticationError):
        P.av_finish(st, dataclasses.replace(m2, VER=b"\x00" * 32), clock)


# -- attacks -----------------------------------------------------------------
def test_session_linking():
    r = A.demo_session_linking(seed=400)
    assert r.success, r.report()


def test_figure_variant_resists_passive_linking():
    """Honest negative result: an outsider cannot link Fig. 3 traffic by TID."""
    pw = [b"x%d" % i for i in range(10)]
    rng, clock, ta, drones, vehicles = A.make_fleet(401, 4, 3, pw)
    log = A.record_traffic(rng, clock, ta, drones, vehicles, 4, "figure")
    assert all(len(g) == 1 for g in A.link_passive(log))


def test_password_guessing():
    r = A.demo_password_guessing(seed=500, dict_size=5000)
    assert r.success, r.report()


def test_password_not_in_dictionary_is_not_found(env):
    *_, av = env
    assert A.guess_password(av.ID, av.obu, [b"a", b"b", b"c"]) is None


def test_guessing_needs_correct_identity(env):
    *_, av = env
    assert A.guess_password(b"\x00" * 20, av.obu, [b"hunter42"]) is None
