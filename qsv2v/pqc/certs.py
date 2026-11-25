"""Short-lived pseudonym certificates and revocation for PQ-V2V-AKE.

Design rules taken from the Phase 4 attacks:

* Vehicles generate their own key pairs; the authority only signs public keys
  and never sees a private key (P2AS-IoAV had the TA generate every key).
* A certificate is the authority's ML-DSA signature over the pseudonym's
  public key and validity window. It is not an algebraic combination of
  authority secrets, so certificates captured from any number of vehicles give
  nothing to solve for (PSRS-D2D's Cert = Pr_TA + MK_TA + h.Pr_TA fell to two).
* The certificate is the only identifier a vehicle ever sends. Each vehicle
  holds a batch of pseudonyms with consecutive validity windows and rotates
  through them (PSLAP sent one static pseudo-identity forever). Only the
  authority can map pseudonyms to a real identity, for revocation.

Encoding is canonical (length-prefixed fields) so that signatures and
digests are unambiguous. ``digest`` is an 8-byte SHA-256 prefix, like the
HashedId8 that IEEE 1609.2 uses to refer to a certificate it has already sent.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace

from qsv2v.crypto.rng import DeterministicRNG
from qsv2v.pqc.sig import MLDSA44, SignatureScheme

CERT_DOMAIN = b"QSV2V-PSEUDONYM-CERT-v1"
CRL_DOMAIN = b"QSV2V-CRL-v1"
PSEUDONYM_LEN = 16


def lp(b: bytes) -> bytes:
    """Length-prefix a field (4-byte big-endian length)."""
    return len(b).to_bytes(4, "big") + b


def read_lp(buf: bytes, off: int) -> tuple[bytes, int]:
    n = int.from_bytes(buf[off : off + 4], "big")
    return buf[off + 4 : off + 4 + n], off + 4 + n


@dataclass(frozen=True)
class PseudonymCert:
    pseudonym: bytes
    sig_alg: str
    public_key: bytes
    not_before: int
    not_after: int
    issuer: bytes  # 8-byte id of the authority key
    signature: bytes = b""

    def tbs(self) -> bytes:
        """The to-be-signed bytes."""
        return (
            CERT_DOMAIN
            + lp(self.pseudonym)
            + lp(self.sig_alg.encode())
            + lp(self.public_key)
            + self.not_before.to_bytes(8, "big")
            + self.not_after.to_bytes(8, "big")
            + lp(self.issuer)
        )

    def encode(self) -> bytes:
        return self.tbs() + lp(self.signature)

    @classmethod
    def decode(cls, buf: bytes) -> PseudonymCert:
        if not buf.startswith(CERT_DOMAIN):
            raise ValueError("not a pseudonym certificate")
        off = len(CERT_DOMAIN)
        pseudonym, off = read_lp(buf, off)
        alg, off = read_lp(buf, off)
        pk, off = read_lp(buf, off)
        nb = int.from_bytes(buf[off : off + 8], "big")
        na = int.from_bytes(buf[off + 8 : off + 16], "big")
        issuer, off = read_lp(buf, off + 16)
        sig, off = read_lp(buf, off)
        if off != len(buf):
            raise ValueError("trailing bytes in certificate")
        return cls(pseudonym, alg.decode(), pk, nb, na, issuer, sig)

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.encode()).digest()[:8]

    def __len__(self) -> int:
        return len(self.encode())


@dataclass(frozen=True)
class CRL:
    """Signed list of revoked pseudonyms."""

    issued_at: int
    revoked: frozenset
    signature: bytes = b""

    def tbs(self) -> bytes:
        return CRL_DOMAIN + self.issued_at.to_bytes(8, "big") + b"".join(sorted(self.revoked))


class CertError(Exception):
    pass


@dataclass
class Credential:
    """A pseudonym certificate plus the private key the vehicle generated for it."""

    cert: PseudonymCert
    secret_key: bytes = field(repr=False)


class Authority:
    """Pseudonym certificate authority. Holds only its own signing key."""

    def __init__(self, rng: DeterministicRNG, scheme: SignatureScheme | None = None):
        self.rng = rng
        self.scheme = scheme or MLDSA44(rng=rng.fork("authority"))
        kp = self.scheme.keygen()
        self.public_key = kp.public_key
        self._secret_key = kp.secret_key
        self.key_id = hashlib.sha256(self.public_key).digest()[:8]
        self._registry: dict[bytes, list[bytes]] = {}  # real id -> pseudonyms (authority only)
        self._revoked: set[bytes] = set()

    def issue(
        self, real_id: bytes, public_key: bytes, sig_alg: str, not_before: int, not_after: int
    ) -> PseudonymCert:
        cert = PseudonymCert(
            pseudonym=self.rng.bytes(PSEUDONYM_LEN),
            sig_alg=sig_alg,
            public_key=public_key,
            not_before=not_before,
            not_after=not_after,
            issuer=self.key_id,
        )
        cert = replace(cert, signature=self.scheme.sign(self._secret_key, cert.tbs()))
        self._registry.setdefault(real_id, []).append(cert.pseudonym)
        return cert

    def enroll(
        self,
        real_id: bytes,
        public_keys: list[bytes],
        proofs: list[bytes],
        scheme: SignatureScheme,
        start: int,
        lifetime: int,
    ) -> list[PseudonymCert]:
        """Certify a batch of vehicle-generated keys with consecutive validity windows.

        ``proofs[i]`` is the vehicle's signature over (real_id || public_keys[i]):
        proof that it holds the private key. Enrollment runs over a secure,
        authenticated channel (as in all three base papers).
        """
        certs = []
        for i, (pk, proof) in enumerate(zip(public_keys, proofs, strict=True)):
            if not scheme.verify(pk, b"QSV2V-POP" + real_id + pk, proof):
                raise CertError("proof of possession failed")
            nb = start + i * lifetime
            certs.append(self.issue(real_id, pk, scheme.name, nb, nb + lifetime))
        return certs

    def revoke(self, real_id: bytes) -> None:
        self._revoked.update(self._registry.get(real_id, []))

    def crl(self, now: int) -> CRL:
        crl = CRL(now, frozenset(self._revoked))
        return replace(crl, signature=self.scheme.sign(self._secret_key, crl.tbs()))


def verify_cert(
    cert: PseudonymCert,
    authority_pk: bytes,
    authority_scheme: SignatureScheme,
    now: int,
    crl: CRL | None = None,
) -> None:
    """Raise CertError unless ``cert`` is authority-signed, current and not revoked."""
    if cert.issuer != hashlib.sha256(authority_pk).digest()[:8]:
        raise CertError("unknown issuer")
    if not authority_scheme.verify(authority_pk, cert.tbs(), cert.signature):
        raise CertError("bad certificate signature")
    if not cert.not_before <= now < cert.not_after:
        raise CertError("certificate not valid now")
    if crl is not None:
        if not authority_scheme.verify(authority_pk, crl.tbs(), crl.signature):
            raise CertError("bad CRL signature")
        if cert.pseudonym in crl.revoked:
            raise CertError("certificate revoked")


def enroll_vehicle(
    authority: Authority,
    real_id: bytes,
    scheme: SignatureScheme,
    n_pseudonyms: int,
    start: int,
    lifetime: int,
) -> list[Credential]:
    """Vehicle side of enrollment: generate keys locally, get them certified."""
    kps = [scheme.keygen() for _ in range(n_pseudonyms)]
    proofs = [scheme.sign(kp.secret_key, b"QSV2V-POP" + real_id + kp.public_key) for kp in kps]
    certs = authority.enroll(
        real_id, [kp.public_key for kp in kps], proofs, scheme, start, lifetime
    )
    return [Credential(c, kp.secret_key) for c, kp in zip(certs, kps, strict=True)]
