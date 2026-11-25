"""ML-KEM-768 (FIPS 203) behind one interface, with two interchangeable backends.

* ``"oqs"``      -- liboqs via liboqs-python (C, fast). Randomness from the OS.
* ``"kyber-py"`` -- pure-Python reference implementation. Deterministic when
  given a :class:`~qsv2v.crypto.rng.DeterministicRNG`, so transcripts are
  reproducible under a fixed seed.

Both implement the final FIPS 203 standard and interoperate (tested).
"""

from __future__ import annotations

from dataclasses import dataclass

from qsv2v.crypto.rng import DeterministicRNG

PK_BYTES, SK_BYTES, CT_BYTES, SS_BYTES = 1184, 2400, 1088, 32


@dataclass(frozen=True)
class KEMKeyPair:
    public_key: bytes
    secret_key: bytes


class MLKEM768:
    name = "ML-KEM-768"

    def __init__(self, backend: str = "kyber-py", rng: DeterministicRNG | None = None):
        if backend not in ("oqs", "kyber-py"):
            raise ValueError("backend must be 'oqs' or 'kyber-py'")
        if backend == "oqs":
            import oqs  # noqa: F401  (fail early if unavailable)
        self.backend = backend
        self.rng = rng

    def _rand(self, n: int) -> bytes:
        import os

        return self.rng.bytes(n) if self.rng is not None else os.urandom(n)

    def keygen(self) -> KEMKeyPair:
        if self.backend == "oqs":
            import oqs

            with oqs.KeyEncapsulation(self.name) as kem:
                pk = kem.generate_keypair()
                return KEMKeyPair(pk, kem.export_secret_key())
        from kyber_py.ml_kem import ML_KEM_768

        ek, dk = ML_KEM_768._keygen_internal(self._rand(32), self._rand(32))
        return KEMKeyPair(ek, dk)

    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret)."""
        if self.backend == "oqs":
            import oqs

            with oqs.KeyEncapsulation(self.name) as kem:
                return kem.encap_secret(public_key)
        from kyber_py.ml_kem import ML_KEM_768

        ss, ct = ML_KEM_768._encaps_internal(public_key, self._rand(32))
        return ct, ss

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        if self.backend == "oqs":
            import oqs

            with oqs.KeyEncapsulation(self.name, secret_key) as kem:
                return kem.decap_secret(ciphertext)
        from kyber_py.ml_kem import ML_KEM_768

        return ML_KEM_768.decaps(secret_key, ciphertext)


class X25519KEM:
    """Classical KEM from X25519 (DHKEM-style), same interface as :class:`MLKEM768`.

    Used for the classical baseline: the same PQ-V2V-AKE code with this KEM and
    ECDSA signatures is today's elliptic-curve design, so its sizes and timings
    are measured with identical framing. ss = HKDF(dh || enc || pk).
    """

    name = "X25519"

    def __init__(self, backend: str = "cryptography", rng: DeterministicRNG | None = None):
        self.rng = rng

    def _priv(self):
        import os

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        return X25519PrivateKey.from_private_bytes(
            self.rng.bytes(32) if self.rng else os.urandom(32)
        )

    @staticmethod
    def _raw_pub(priv) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def _ss(dh: bytes, enc: bytes, pk: bytes) -> bytes:
        import hashlib
        import hmac

        prk = hmac.new(b"X25519-KEM", dh + enc + pk, hashlib.sha256).digest()
        return hmac.new(prk, b"shared secret\x01", hashlib.sha256).digest()

    def keygen(self) -> KEMKeyPair:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        priv = self._priv()
        sk = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return KEMKeyPair(self._raw_pub(priv), sk)

    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        eph = self._priv()
        enc = self._raw_pub(eph)
        dh = eph.exchange(X25519PublicKey.from_public_bytes(public_key))
        return enc, self._ss(dh, enc, public_key)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )

        priv = X25519PrivateKey.from_private_bytes(secret_key)
        dh = priv.exchange(X25519PublicKey.from_public_bytes(ciphertext))
        return self._ss(dh, ciphertext, self._raw_pub(priv))


def get_kem(name: str, backend: str = "kyber-py", rng: DeterministicRNG | None = None):
    if name == "ML-KEM-768":
        return MLKEM768(backend, rng)
    if name == "X25519":
        return X25519KEM(rng=rng)
    raise ValueError(f"unknown KEM {name!r}")
