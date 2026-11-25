"""Signatures behind one interface: ML-DSA-44 (FIPS 204), Falcon-512, and ECDSA P-256.

* ML-DSA-44: ``"oqs"`` (liboqs) or ``"dilithium-py"`` (pure Python; deterministic
  keygen and signing from a :class:`DeterministicRNG`). The two interoperate.
* Falcon-512: liboqs only (no pure-Python implementation is bundled).
* ECDSA P-256: the classical baseline (``cryptography``), raw r||s signatures,
  used for size and timing comparisons only.
"""

from __future__ import annotations

from dataclasses import dataclass

from qsv2v.crypto.rng import DeterministicRNG


@dataclass(frozen=True)
class SigKeyPair:
    public_key: bytes
    secret_key: bytes


class SignatureScheme:
    name: str = "abstract"

    def keygen(self) -> SigKeyPair:
        raise NotImplementedError

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        raise NotImplementedError


def oqs_available() -> bool:
    try:
        import oqs  # noqa: F401
    except Exception:
        return False
    return True


class _OQSSig(SignatureScheme):
    def keygen(self) -> SigKeyPair:
        import oqs

        with oqs.Signature(self.name) as s:
            pk = s.generate_keypair()
            return SigKeyPair(pk, s.export_secret_key())

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        import oqs

        with oqs.Signature(self.name, secret_key) as s:
            return s.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        import oqs

        try:
            with oqs.Signature(self.name) as s:
                return bool(s.verify(message, signature, public_key))
        except Exception:
            return False


class MLDSA44(SignatureScheme):
    name = "ML-DSA-44"

    def __init__(self, backend: str = "dilithium-py", rng: DeterministicRNG | None = None):
        if backend not in ("oqs", "dilithium-py"):
            raise ValueError("backend must be 'oqs' or 'dilithium-py'")
        self.backend = backend
        self.rng = rng
        self._oqs = _OQSSig() if backend == "oqs" else None
        if self._oqs:
            self._oqs.name = self.name

    def keygen(self) -> SigKeyPair:
        if self._oqs:
            return self._oqs.keygen()
        import os

        from dilithium_py.ml_dsa import ML_DSA_44

        seed = self.rng.bytes(32) if self.rng else os.urandom(32)
        pk, sk = ML_DSA_44._keygen_internal(seed)
        return SigKeyPair(pk, sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if self._oqs:
            return self._oqs.sign(secret_key, message)
        from dilithium_py.ml_dsa import ML_DSA_44

        return ML_DSA_44.sign(secret_key, message, deterministic=self.rng is not None)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if self._oqs:
            return self._oqs.verify(public_key, message, signature)
        from dilithium_py.ml_dsa import ML_DSA_44

        try:
            return bool(ML_DSA_44.verify(public_key, message, signature))
        except Exception:
            return False


class Falcon512(_OQSSig):
    name = "Falcon-512"

    def __init__(self):
        if not oqs_available():
            raise RuntimeError("Falcon-512 needs liboqs-python (pip install -e '.[oqs]')")


class ECDSAP256(SignatureScheme):
    """Classical baseline. Raw 64-byte r||s signatures, 64-byte x||y public keys."""

    name = "ECDSA-P256"

    def __init__(self, rng: DeterministicRNG | None = None):
        self.rng = rng

    def keygen(self) -> SigKeyPair:
        from cryptography.hazmat.primitives.asymmetric import ec

        from qsv2v.crypto.ec import Q

        if self.rng:
            priv = ec.derive_private_key(self.rng.scalar(Q), ec.SECP256R1())
        else:
            priv = ec.generate_private_key(ec.SECP256R1())
        nums = priv.public_key().public_numbers()
        pk = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
        return SigKeyPair(pk, priv.private_numbers().private_value.to_bytes(32, "big"))

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        priv = ec.derive_private_key(int.from_bytes(secret_key, "big"), ec.SECP256R1())
        r, s = decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        try:
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(public_key[:32], "big"),
                int.from_bytes(public_key[32:], "big"),
                ec.SECP256R1(),
            ).public_key()
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            )
            pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


def get_scheme(name: str, backend: str = "dilithium-py", rng=None) -> SignatureScheme:
    if name == "ML-DSA-44":
        return MLDSA44(backend, rng)
    if name == "Falcon-512":
        return Falcon512()
    if name == "ECDSA-P256":
        return ECDSAP256(rng)
    raise ValueError(f"unknown signature scheme {name!r}")
