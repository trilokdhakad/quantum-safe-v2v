import pytest
from conftest import within_sigmas
from cryptography.exceptions import InvalidTag

from qsv2v.crypto import (
    DeterministicRNG,
    G,
    Q,
    aead_decrypt,
    aead_encrypt,
    hash_to_scalar,
    point_bytes,
    point_from_bytes,
    xor_bytes,
)


def test_drbg_deterministic_and_seed_sensitive():
    assert DeterministicRNG(1).bytes(64) == DeterministicRNG(1).bytes(64)
    assert DeterministicRNG(1).bytes(32) != DeterministicRNG(2).bytes(32)
    assert DeterministicRNG("a").bytes(8) == DeterministicRNG(b"a").bytes(8)
    r = DeterministicRNG(3)
    assert r.bytes(10) != r.bytes(10)  # stream advances


def test_drbg_randbelow_uniform():
    r = DeterministicRNG(4)
    vals = [r.randbelow(10) for _ in range(20_000)]
    assert min(vals) == 0 and max(vals) == 9
    assert within_sigmas(sum(v == 7 for v in vals) / len(vals), 0.1, len(vals))
    assert 1 <= r.scalar(Q) < Q
    with pytest.raises(ValueError):
        r.randbelow(0)


def test_drbg_fork_independent():
    r = DeterministicRNG(5)
    a, b = r.fork("x"), r.fork("x")
    assert a.bytes(16) != b.bytes(16)


def test_point_roundtrip_and_validation():
    p = 12345 * G
    assert point_from_bytes(point_bytes(p)) == p
    bad = bytearray(point_bytes(p))
    bad[-1] ^= 1
    with pytest.raises(ValueError):
        point_from_bytes(bytes(bad))
    with pytest.raises(ValueError):
        point_from_bytes(b"\x00" * 10)


def test_hash_to_scalar_range():
    assert 0 <= hash_to_scalar(b"abc") < Q
    assert hash_to_scalar(b"a", b"b") == hash_to_scalar(b"ab")


def test_aead_roundtrip_and_tamper():
    key, nonce = b"k" * 32, b"n" * 12
    blob = aead_encrypt(key, b"hello", nonce, b"aad")
    assert aead_decrypt(key, blob, b"aad") == b"hello"
    with pytest.raises(InvalidTag):
        aead_decrypt(key, blob[:-1] + bytes([blob[-1] ^ 1]), b"aad")
    with pytest.raises(InvalidTag):
        aead_decrypt(b"x" * 32, blob, b"aad")
    with pytest.raises(ValueError):
        aead_encrypt(key, b"", b"short")


def test_xor():
    assert xor_bytes(b"\x0f\xf0", b"\xff\xff") == b"\xf0\x0f"
    with pytest.raises(ValueError):
        xor_bytes(b"a", b"ab")
