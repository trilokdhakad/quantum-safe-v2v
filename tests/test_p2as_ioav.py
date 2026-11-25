import dataclasses

import pytest
from conftest import KEM_BACKENDS
from cryptography.exceptions import InvalidTag

from qsv2v.attacks.common import AuthenticationError, SimClock
from qsv2v.attacks.p2as_ioav import attacks as A
from qsv2v.attacks.p2as_ioav import protocol as P


@pytest.fixture(params=KEM_BACKENDS)
def backend(request):
    return request.param


@pytest.fixture
def env(backend):
    return A.make_network(31, 2, 2, backend)


# -- protocol as printed ----------------------------------------------------
def test_honest_handshake(env):
    rng, kem, ta, avs, drs = env
    s = P.handshake(kem, avs[0], drs[0], ta, SimClock(), rng, b"data")
    assert len(s.sk) == 32


def test_tampered_msg1_rejected(env):
    """The drone does check something: a modified V1 fails."""
    rng, kem, ta, avs, drs = env
    clock = SimClock()
    m1, _ = P.av_initiate(kem, avs[0], drs[0].pu, clock, rng)
    with pytest.raises(AuthenticationError):
        P.drone_respond(
            kem, drs[0], dataclasses.replace(m1, V1=b"\x00" * 32), ta.directory, clock, rng
        )


def test_stale_msg1_rejected(env):
    rng, kem, ta, avs, drs = env
    clock = SimClock()
    m1, _ = P.av_initiate(kem, avs[0], drs[0].pu, clock, rng)
    clock.advance(60)
    with pytest.raises(AuthenticationError, match="stale"):
        P.drone_respond(kem, drs[0], m1, ta.directory, clock, rng)


# -- attacks -----------------------------------------------------------------
def test_forged_msg1_accepted(backend):
    r = A.demo_forged_msg1(seed=600, kem_backend=backend)
    assert r.success, r.report()


def test_forged_msg1_for_unregistered_id_is_rejected(env):
    rng, kem, ta, avs, drs = env
    clock = SimClock()
    m1 = A.forge_msg1(kem, b"\x99" * 20, drs[0].pu, clock, rng)
    with pytest.raises(AuthenticationError, match="unknown"):
        P.drone_respond(kem, drs[0], m1, ta.directory, clock, rng)


def test_past_session_decryption(backend):
    r = A.demo_past_session_decryption(seed=700, kem_backend=backend)
    assert r.success, r.report()


def test_one_leaked_key_is_not_enough_for_sk(env):
    """Honest limit: with the drone key but the wrong vehicle key, SK is not recovered."""
    rng, kem, ta, avs, drs = env
    s = P.handshake(kem, avs[0], drs[0], ta, SimClock(), rng, b"secret")
    s_i, id_av, _ = A.unwrap_msg1(kem, drs[0].pr, s.m1)
    assert id_av == avs[0].ID and s_i == avs[0].s  # de-anonymised
    with pytest.raises(InvalidTag):
        A.recover_past_session(kem, drs[0].pr, avs[1].pr, s)
