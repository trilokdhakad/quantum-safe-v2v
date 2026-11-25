import dataclasses

import pytest

from qsv2v.crypto import DeterministicRNG
from qsv2v.pqc.certs import (
    Authority,
    CertError,
    PseudonymCert,
    enroll_vehicle,
    verify_cert,
)
from qsv2v.pqc.sig import MLDSA44

T0 = 1_790_000_000


@pytest.fixture
def ca():
    rng = DeterministicRNG(41)
    return Authority(rng, MLDSA44(rng=rng.fork("ca")))


@pytest.fixture
def creds(ca):
    return enroll_vehicle(ca, b"VIN-A", MLDSA44(rng=DeterministicRNG(42)), 3, T0, 300)


def test_enrollment_gives_consecutive_windows(ca, creds):
    assert [c.cert.not_before for c in creds] == [T0, T0 + 300, T0 + 600]
    assert len({c.cert.pseudonym for c in creds}) == 3
    assert len({c.cert.public_key for c in creds}) == 3
    for c in creds:
        verify_cert(c.cert, ca.public_key, ca.scheme, c.cert.not_before)


def test_authority_never_holds_vehicle_private_keys(ca, creds):
    held = repr(vars(ca))
    assert all(c.secret_key.hex() not in held for c in creds)


def test_encode_decode_roundtrip(creds):
    c = creds[0].cert
    assert PseudonymCert.decode(c.encode()) == c
    with pytest.raises(ValueError):
        PseudonymCert.decode(c.encode() + b"x")
    with pytest.raises(ValueError):
        PseudonymCert.decode(b"junk")


def test_rejections(ca, creds):
    c = creds[0].cert
    with pytest.raises(CertError, match="not valid"):
        verify_cert(c, ca.public_key, ca.scheme, T0 + 300)
    with pytest.raises(CertError, match="signature"):
        verify_cert(dataclasses.replace(c, not_after=T0 + 10**6), ca.public_key, ca.scheme, T0)
    other = Authority(DeterministicRNG(7))
    with pytest.raises(CertError, match="issuer"):
        verify_cert(c, other.public_key, other.scheme, T0)


def test_revocation_covers_all_pseudonyms(ca, creds):
    ca.revoke(b"VIN-A")
    crl = ca.crl(T0)
    for c in creds:
        with pytest.raises(CertError, match="revoked"):
            verify_cert(c.cert, ca.public_key, ca.scheme, c.cert.not_before, crl)
    forged = dataclasses.replace(crl, revoked=frozenset())
    with pytest.raises(CertError, match="CRL"):
        verify_cert(creds[0].cert, ca.public_key, ca.scheme, T0, forged)


def test_proof_of_possession_required(ca):
    s = MLDSA44(rng=DeterministicRNG(5))
    kp = s.keygen()
    with pytest.raises(CertError, match="possession"):
        ca.enroll(b"VIN-B", [kp.public_key], [b"\0" * 2420], s, T0, 300)
