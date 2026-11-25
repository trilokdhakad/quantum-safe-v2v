import dataclasses

import pytest
from conftest import OQS

from qsv2v.crypto import DeterministicRNG
from qsv2v.pqc.broadcast import (
    FRAME_LIMIT,
    SPDU,
    Broadcaster,
    BroadcastError,
    Receiver,
    bsm_payload,
    size_table,
)
from qsv2v.pqc.certs import Authority, enroll_vehicle
from qsv2v.pqc.sig import MLDSA44

T0 = 1_790_000_000


@pytest.fixture
def setup():
    rng = DeterministicRNG(61)
    ca = Authority(rng.fork("ca"))
    sch = MLDSA44(rng=rng.fork("v"))
    cred = enroll_vehicle(ca, b"VIN", sch, 1, T0, 300)[0]
    return ca, sch, Broadcaster(cred, sch), Receiver(ca.public_key, ca.scheme, {sch.name: sch})


def test_cert_then_digest(setup):
    _, _, tx, rx = setup
    msgs = [tx.sign(bsm_payload(i), T0) for i in range(12)]
    assert [m.full_cert for m in msgs] == [True] + [False] * 9 + [True, False]
    for i, m in enumerate(msgs):
        assert rx.accept(m.encode(), T0) == bsm_payload(i)


def test_digest_before_cert_is_rejected(setup):
    _, _, tx, rx = setup
    tx.sign(bsm_payload(0), T0)  # receiver missed this one
    with pytest.raises(BroadcastError, match="unknown signer"):
        rx.accept(tx.sign(bsm_payload(1), T0).encode(), T0)


def test_tampered_and_stale_rejected(setup):
    _, _, tx, rx = setup
    m = tx.sign(bsm_payload(0), T0)
    bad = dataclasses.replace(m, payload=bsm_payload(99))
    with pytest.raises(BroadcastError, match="signature"):
        rx.accept(bad.encode(), T0)
    with pytest.raises(BroadcastError, match="stale"):
        rx.accept(m.encode(), T0 + 10)


def test_spdu_roundtrip(setup):
    _, _, tx, _ = setup
    m = tx.sign(bsm_payload(0), T0)
    assert SPDU.decode(m.encode()) == m
    with pytest.raises(BroadcastError):
        SPDU.decode(b"XYZ")


@pytest.mark.skipif(not OQS, reason="Falcon-512 needs liboqs")
def test_size_table_e8():
    """E8: ML-DSA-44 overflows a frame even with a digest; Falcon-512 + digest fits."""
    rows = {r["vehicle_alg"] + "/" + r["authority_alg"]: r for r in size_table()}
    ecdsa = rows["ECDSA-P256/ECDSA-P256"]
    assert ecdsa["cert_msg_fits_frame"] and ecdsa["digest_msg_fits_frame"]
    assert rows["Falcon-512/Falcon-512"]["digest_msg_fits_frame"]
    assert not rows["Falcon-512/Falcon-512"]["cert_msg_fits_frame"]
    mldsa = rows["ML-DSA-44/ML-DSA-44"]
    assert not mldsa["digest_msg_fits_frame"] and mldsa["msg_with_digest_bytes"] > FRAME_LIMIT
