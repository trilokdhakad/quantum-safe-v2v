import pytest
from conftest import KEM_BACKENDS, OQS

from qsv2v.crypto import DeterministicRNG
from qsv2v.pqc.kem import CT_BYTES, MLKEM768, PK_BYTES, SS_BYTES


@pytest.fixture(params=KEM_BACKENDS)
def kem(request):
    return MLKEM768(request.param, rng=DeterministicRNG(1))


def test_roundtrip_and_fips203_sizes(kem):
    kp = kem.keygen()
    ct, ss = kem.encaps(kp.public_key)
    assert len(kp.public_key) == PK_BYTES and len(ct) == CT_BYTES and len(ss) == SS_BYTES
    assert kem.decaps(kp.secret_key, ct) == ss


def test_wrong_key_gives_different_secret(kem):
    a, b = kem.keygen(), kem.keygen()
    ct, ss = kem.encaps(a.public_key)
    assert kem.decaps(b.secret_key, ct) != ss  # implicit rejection


@pytest.mark.skipif(not OQS, reason="liboqs-python unavailable")
@pytest.mark.parametrize("enc,dec", [("kyber-py", "oqs"), ("oqs", "kyber-py")])
def test_backends_interoperate(enc, dec):
    """Both are FIPS 203 ML-KEM-768: keys and ciphertexts are interchangeable."""
    kp = MLKEM768(dec, rng=DeterministicRNG(2)).keygen()
    ct, ss = MLKEM768(enc, rng=DeterministicRNG(3)).encaps(kp.public_key)
    assert MLKEM768(dec).decaps(kp.secret_key, ct) == ss


def test_kyber_py_deterministic_with_seed():
    a = MLKEM768("kyber-py", rng=DeterministicRNG(7))
    b = MLKEM768("kyber-py", rng=DeterministicRNG(7))
    ka, kb = a.keygen(), b.keygen()
    assert ka == kb
    assert a.encaps(ka.public_key) == b.encaps(kb.public_key)


def test_bad_backend():
    with pytest.raises(ValueError):
        MLKEM768("nope")
