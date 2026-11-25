import dataclasses

import pytest

from qsv2v.attacks.common import AuthenticationError, SimClock
from qsv2v.attacks.psrs_d2d import attacks as A
from qsv2v.attacks.psrs_d2d import protocol as P
from qsv2v.crypto import DeterministicRNG, G, Q


@pytest.fixture
def net():
    rng = DeterministicRNG(11)
    return rng, P.build_network(6, rng)


# -- protocol as printed ----------------------------------------------------
def test_honest_handshake(net):
    rng, n = net
    s = P.handshake(n.drones[0], n.drones[1], n.directory, SimClock(), rng)
    assert len(s.sk) == 32


def test_printed_step2_equation_rejects_honest_drones(net):
    """h(Pub_j||ID_TA||ID_j||Pub_TA) in step 2 can never verify Cert_i."""
    rng, n = net
    with pytest.raises(AuthenticationError, match="certificate"):
        P.handshake(n.drones[0], n.drones[1], n.directory, SimClock(), rng, as_printed=True)


def test_certificate_identity(net):
    _, n = net
    d = n.drones[2]
    assert d.Cert * G == P.cert_public_point(d.Pub, d.ID, n.ta.public)


def test_rejects_stale_and_tampered(net):
    rng, n = net
    di, dj = n.drones[0], n.drones[1]
    clock = SimClock()
    m1, _ = P.initiate(di, dj.Pub, clock, rng)
    clock.advance(100)
    with pytest.raises(AuthenticationError, match="stale"):
        P.respond(dj, m1, n.directory, clock, rng)
    clock = SimClock()
    m1, _ = P.initiate(di, dj.Pub, clock, rng)
    with pytest.raises(AuthenticationError):
        P.respond(dj, dataclasses.replace(m1, ADC=(m1.ADC + 1) % Q), n.directory, clock, rng)
    with pytest.raises(AuthenticationError):
        P.respond(dj, dataclasses.replace(m1, U=b"\x00" * 32), n.directory, clock, rng)


# -- attacks -----------------------------------------------------------------
@pytest.mark.parametrize("seed", range(3))
def test_passive_session_key_recovery(seed):
    r = A.demo_session_key_recovery(seed=seed + 100, n_drones=12)
    assert r.success, r.report()


def test_passive_recovery_every_pair(net):
    rng, n = net
    clock = SimClock()
    for i, di in enumerate(n.drones):
        for dj in n.drones[i + 1 :]:
            s = P.handshake(di, dj, n.directory, clock, rng)
            out = A.passive_session_key_recovery(s, n.directory, n.ta.public)
            assert out["SK"] == s.sk and out["ID_i"] == di.ID and out["ID_j"] == dj.ID
            assert out["confirmed"]
            clock.advance(30)


def test_passive_recovery_needs_sender_in_directory(net):
    rng, n = net
    s = P.handshake(n.drones[0], n.drones[1], n.directory, SimClock(), rng)
    partial = {k: v for k, v in n.directory.items() if k != n.drones[0].ID}
    assert A.unmask_sender(s.m1.ADC, s.m1.IDbar, partial, n.ta.public) == (None, None)


def test_forward_secrecy_break():
    r = A.demo_forward_secrecy(seed=200, n_sessions=6)
    assert r.success, r.report()
    assert sum("initiator" in k for k in r.expected) == 3  # both roles exercised


def test_master_key_extraction_and_impersonation():
    r = A.demo_master_key_extraction(seed=300)
    assert r.success, r.report()


def test_master_keys_from_any_two_drones(net):
    _, n = net
    for a, b in [(0, 1), (2, 5), (4, 3)]:
        assert A.extract_master_keys(n.drones[a], n.drones[b]) == (n.ta.Pr_TA, n.ta.MK_TA)
