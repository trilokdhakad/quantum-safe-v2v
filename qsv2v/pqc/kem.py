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
