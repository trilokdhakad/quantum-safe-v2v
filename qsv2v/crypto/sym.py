"""Hashing, XOR and AES-256-GCM helpers."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def h(*parts: bytes) -> bytes:
    """SHA-256 over the concatenation of fixed-width parts (the papers' h(a||b||...))."""
    return hashlib.sha256(b"".join(parts)).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor operands must have equal length")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def aead_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM; returns nonce || ciphertext || tag."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Inverse of :func:`aead_encrypt`; raises ``cryptography.exceptions.InvalidTag``."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
