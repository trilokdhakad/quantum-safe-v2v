import dataclasses

import pytest
from conftest import OQS

from qsv2v.attacks.common import AuthenticationError
from qsv2v.pqc import pq_v2v_ake as A


@pytest.fixture(params=[False, True], ids=["pq-only", "hybrid"])
def net(request):
    return A.setup_network(2, seed=51, hybrid=request.param)


def test_handshake_agrees_on_key_and_peers(net):
    vi, vr = net.vehicles
    tr = A.handshake(vi, vr, net.clock)
    assert tr.initiator.key == tr.responder.key and len(tr.initiator.key) == 32
    assert tr.initiator.peer_pseudonym == vr.credential(net.clock.now()).cert.pseudonym
    assert tr.responder.peer_pseudonym == vi.credential(net.clock.now()).cert.pseudonym


def test_fresh_key_every_session(net):
    vi, vr = net.vehicles
    k1 = A.handshake(vi, vr, net.clock).initiator.key
    k2 = A.handshake(vi, vr, net.clock).initiator.key
    assert k1 != k2


def test_message_sizes(net):
    tr = A.handshake(*net.vehicles, net.clock)
    s = tr.sizes
    assert 7000 < s["m1"] < 8000 and 7000 < s["m2"] < 8000 and s["m3"] < 64


def test_ephemeral_key_erased_and_single_use(net):
    vi, vr = net.vehicles
    m1, st = A.initiate(vi, net.clock)
    m2, _ = A.respond(vr, m1, net.clock)
    A.finish(vi, st, m2, net.clock)
    assert st.dk is None
    with pytest.raises(AuthenticationError, match="already used"):
        A.finish(vi, st, m2, net.clock)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ct", b"\0" * 1088),
        ("nonce", b"\1" * 32),
        ("ts", 0),
        ("sig", b"\0" * 2420),
        ("mac", b"\0" * 32),
    ],
)
def test_tampered_msg2_rejected(net, field, value):
    vi, vr = net.vehicles
    m1, st = A.initiate(vi, net.clock)
    m2, _ = A.respond(vr, m1, net.clock)
    with pytest.raises(AuthenticationError):
        A.finish(vi, st, dataclasses.replace(m2, **{field: value}), net.clock)


def test_tampered_msg3_rejected(net):
    vi, vr = net.vehicles
    m1, st = A.initiate(vi, net.clock)
    m2, st_r = A.respond(vr, m1, net.clock)
    A.finish(vi, st, m2, net.clock)
    with pytest.raises(AuthenticationError, match="confirmation"):
        A.confirm(st_r, A.Msg3(b"\0" * 32))


def test_mode_mismatch_rejected():
    a = A.setup_network(2, seed=52, hybrid=False)
    a.vehicles[1].config.hybrid = True
    m1, _ = A.initiate(a.vehicles[0], a.clock)
    with pytest.raises(AuthenticationError, match="hybrid"):
        A.respond(a.vehicles[1], m1, a.clock)


def test_pseudonym_rotation(net):
    vi, vr = net.vehicles
    p1 = A.handshake(vi, vr, net.clock).responder.peer_pseudonym
    net.clock.advance(300)
    p2 = A.handshake(vi, vr, net.clock).responder.peer_pseudonym
    assert p1 != p2


def test_no_valid_pseudonym_left(net):
    net.clock.advance(10_000)
    with pytest.raises(Exception, match="no valid pseudonym"):
        A.initiate(net.vehicles[0], net.clock)


def test_hkdf_rfc5869_vector():
    """RFC 5869 test case 1."""
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = A.hkdf_extract(salt, ikm)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert A.hkdf_expand(prk, info, 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


@pytest.mark.skipif(not OQS, reason="liboqs-python unavailable")
def test_handshake_on_liboqs():
    net = A.setup_network(2, seed=53, kem_backend="oqs", sig_backend="oqs")
    tr = A.handshake(*net.vehicles, net.clock)
    assert tr.initiator.key == tr.responder.key
