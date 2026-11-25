"""Signed broadcast safety messages (BSM / CAM) with post-quantum signatures.

Every vehicle broadcasts a safety message about 10 times a second; each one is
signed so receivers can trust it. Following IEEE 1609.2 practice, a message
carries the sender's full pseudonym certificate only occasionally (default:
once per second, or when asked), and otherwise just the certificate's 8-byte
digest; receivers cache certificates they have verified.

Wire format (canonical, length-prefixed):

    "BSM" || alg || gen_time(8) || signer_type(1) || signer || payload || signature

where signer is the full certificate (type 1) or its digest (type 0) and the
signature covers everything before it.

The question this module answers (experiment E8): which schemes fit a safety
message into one ~1,400-byte radio frame?
"""

from __future__ import annotations

from dataclasses import dataclass, field

from qsv2v.pqc.certs import CRL, CertError, Credential, PseudonymCert, lp, read_lp, verify_cert
from qsv2v.pqc.sig import SignatureScheme

FRAME_LIMIT = 1400  # usable bytes in one 802.11p / C-V2X frame, as in the project plan
CERT_EVERY = 10  # attach the full certificate on every 10th message (1 s at 10 Hz)
DOMAIN = b"BSM"


class BroadcastError(Exception):
    pass


@dataclass
class SPDU:
    """A signed safety message as sent on air."""

    alg: str
    gen_time: int
    full_cert: bool
    signer: bytes
    payload: bytes
    signature: bytes

    def tbs(self) -> bytes:
        return (
            DOMAIN + lp(self.alg.encode()) + self.gen_time.to_bytes(8, "big")
            + bytes([1 if self.full_cert else 0]) + lp(self.signer) + lp(self.payload)
        )  # fmt: skip

    def encode(self) -> bytes:
        return self.tbs() + lp(self.signature)

    @classmethod
    def decode(cls, buf: bytes) -> SPDU:
        if not buf.startswith(DOMAIN):
            raise BroadcastError("not a safety message")
        alg, off = read_lp(buf, len(DOMAIN))
        gen = int.from_bytes(buf[off : off + 8], "big")
        full = buf[off + 8] == 1
        signer, off = read_lp(buf, off + 9)
        payload, off = read_lp(buf, off)
        sig, off = read_lp(buf, off)
        if off != len(buf):
            raise BroadcastError("trailing bytes")
        return cls(alg.decode(), gen, full, signer, payload, sig)

    def __len__(self) -> int:
        return len(self.encode())


@dataclass
class Broadcaster:
    credential: Credential
    scheme: SignatureScheme
    cert_every: int = CERT_EVERY
    counter: int = 0

    def sign(self, payload: bytes, gen_time: int, force_cert: bool = False) -> SPDU:
        full = force_cert or self.counter % self.cert_every == 0
        self.counter += 1
        cert = self.credential.cert
        signer = cert.encode() if full else cert.digest
        msg = SPDU(self.scheme.name, gen_time, full, signer, payload, b"")
        msg.signature = self.scheme.sign(self.credential.secret_key, msg.tbs())
        return msg


@dataclass
class Receiver:
    authority_pk: bytes
    authority_scheme: SignatureScheme
    schemes: dict[str, SignatureScheme]
    crl: CRL | None = None
    max_age: int = 2  # seconds
    cache: dict[bytes, PseudonymCert] = field(default_factory=dict)

    def accept(self, wire: bytes, now: int) -> bytes:
        """Return the payload of a valid message; raise BroadcastError otherwise."""
        msg = SPDU.decode(wire)
        if not 0 <= now - msg.gen_time <= self.max_age:
            raise BroadcastError("stale or future message")
        if msg.full_cert:
            try:
                cert = PseudonymCert.decode(msg.signer)
                verify_cert(cert, self.authority_pk, self.authority_scheme, now, self.crl)
            except (CertError, ValueError) as e:
                raise BroadcastError(f"certificate rejected: {e}") from e
            self.cache[cert.digest] = cert
        else:
            cert = self.cache.get(msg.signer)
            if cert is None:
                raise BroadcastError("unknown signer digest (certificate not yet received)")
            if not cert.not_before <= now < cert.not_after:
                raise BroadcastError("cached certificate expired")
        if cert.sig_alg != msg.alg or msg.alg not in self.schemes:
            raise BroadcastError("algorithm mismatch")
        if not self.schemes[msg.alg].verify(cert.public_key, msg.tbs(), msg.signature):
            raise BroadcastError("bad signature")
        return msg.payload


def bsm_payload(seq: int, size: int = 200) -> bytes:
    """Synthetic safety-message payload of ``size`` bytes (position, speed, heading...).

    SAE J2735 BSMs are typically a few hundred bytes; 200 is the default here
    and is a stated assumption of the size experiments.
    """
    head = b"BSM seq=%08d lat=25.204800 lon=55.270800 v=27.8 hdg=090" % seq
    return (head + b"\x00" * size)[:size]


CONFIGS = [
    # (label, vehicle signature scheme, authority signature scheme)
    ("ECDSA P-256 (today, IEEE 1609.2)", "ECDSA-P256", "ECDSA-P256"),
    ("Falcon-512, Falcon-512 authority", "Falcon-512", "Falcon-512"),
    ("Falcon-512, ML-DSA-44 authority", "Falcon-512", "ML-DSA-44"),
    ("ML-DSA-44, ML-DSA-44 authority", "ML-DSA-44", "ML-DSA-44"),
]


def size_table(payload_size: int = 200, seed: int = 0, sig_backend: str = "dilithium-py"):
    """Measure on-air sizes of a safety message for each configuration (real signatures).

    Returns one row per configuration with the certificate size and the size
    of a message carrying the full certificate and one carrying only the digest.
    """
    from qsv2v.crypto.rng import DeterministicRNG
    from qsv2v.pqc.certs import Authority, enroll_vehicle
    from qsv2v.pqc.sig import get_scheme

    rng = DeterministicRNG(seed)
    t0 = 1_790_000_000
    rows = []
    for label, veh_alg, ca_alg in CONFIGS:
        ca_scheme = get_scheme(ca_alg, sig_backend, rng.fork("ca-" + label))
        ca = Authority(rng.fork("ca-rng-" + label), ca_scheme)
        veh = get_scheme(veh_alg, sig_backend, rng.fork("veh-" + label))
        cred = enroll_vehicle(ca, b"VIN-0001", veh, 1, t0, 300)[0]
        b = Broadcaster(cred, veh)
        rx = Receiver(ca.public_key, ca_scheme, {veh.name: veh})
        full = b.sign(bsm_payload(0, payload_size), t0, force_cert=True)
        dig = b.sign(bsm_payload(1, payload_size), t0)
        rx.accept(full.encode(), t0)
        rx.accept(dig.encode(), t0)  # both verified for real
        avg = (len(full) + (CERT_EVERY - 1) * len(dig)) / CERT_EVERY
        rows.append(
            {
                "config": label,
                "vehicle_alg": veh_alg,
                "authority_alg": ca_alg,
                "payload_bytes": payload_size,
                "cert_bytes": len(cred.cert),
                "signature_bytes": len(dig.signature),
                "msg_with_cert_bytes": len(full),
                "msg_with_digest_bytes": len(dig),
                "avg_bytes_per_msg": round(avg, 1),
                "digest_msg_fits_frame": len(dig) <= FRAME_LIMIT,
                "cert_msg_fits_frame": len(full) <= FRAME_LIMIT,
            }
        )
    return rows
