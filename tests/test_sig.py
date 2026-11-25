import pytest
from conftest import OQS

from qsv2v.crypto import DeterministicRNG
from qsv2v.pqc.sig import ECDSAP256, MLDSA44, Falcon512, get_scheme

needs_oqs = pytest.mark.skipif(not OQS, reason="liboqs-python unavailable")

SCHEMES = [
    ("ML-DSA-44/dilithium-py", lambda: MLDSA44("dilithium-py", DeterministicRNG(1)), 1312, 2420),
    pytest.param("ML-DSA-44/oqs", lambda: MLDSA44("oqs"), 1312, 2420, marks=needs_oqs),
    pytest.param("Falcon-512", lambda: Falcon512(), 897, None, marks=needs_oqs),
    ("ECDSA-P256", lambda: ECDSAP256(DeterministicRNG(2)), 64, 64),
]


@pytest.mark.parametrize("name,make,pk_len,sig_len", SCHEMES)
def test_sign_verify_and_sizes(name, make, pk_len, sig_len):
    s = make()
    kp = s.keygen()
    sig = s.sign(kp.secret_key, b"hello V2V")
    assert len(kp.public_key) == pk_len
    if sig_len:
        assert len(sig) == sig_len
    else:
        assert 600 < len(sig) <= 752  # Falcon-512 signatures are variable length
    assert s.verify(kp.public_key, b"hello V2V", sig)
    assert not s.verify(kp.public_key, b"hello V2W", sig)
    assert not s.verify(s.keygen().public_key, b"hello V2V", sig)
    assert not s.verify(kp.public_key, b"hello V2V", sig[:-1] + bytes([sig[-1] ^ 1]))


def test_dilithium_py_deterministic():
    a, b = MLDSA44(rng=DeterministicRNG(9)), MLDSA44(rng=DeterministicRNG(9))
    ka, kb = a.keygen(), b.keygen()
    assert ka == kb and a.sign(ka.secret_key, b"m") == b.sign(kb.secret_key, b"m")


@needs_oqs
def test_mldsa_backends_interoperate():
    kp = MLDSA44("dilithium-py", DeterministicRNG(3)).keygen()
    sig = MLDSA44("dilithium-py", DeterministicRNG(3)).sign(kp.secret_key, b"m")
    assert MLDSA44("oqs").verify(kp.public_key, b"m", sig)
    kp2 = MLDSA44("oqs").keygen()
    assert MLDSA44("dilithium-py").verify(
        kp2.public_key, b"m", MLDSA44("oqs").sign(kp2.secret_key, b"m")
    )


def test_get_scheme():
    assert get_scheme("ML-DSA-44").name == "ML-DSA-44"
    assert get_scheme("ECDSA-P256").name == "ECDSA-P256"
    with pytest.raises(ValueError):
        get_scheme("RSA")
    with pytest.raises(ValueError):
        MLDSA44("nope")
