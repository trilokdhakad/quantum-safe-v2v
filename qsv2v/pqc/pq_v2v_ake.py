"""PQ-V2V-AKE: post-quantum authenticated key exchange between two vehicles.

Three messages (I = initiator, R = responder; Cert_X = pseudonym certificate):

    m1  I -> R : ek_e, [X_I], Cert_I, N_I, T_I, sig_I = Sign_I("m1" || th1-body)
    m2  R -> I : ct, [X_R], Cert_R, N_R, T_R, sig_R = Sign_R(th2), mac_R
    m3  I -> R : mac_I

    (ct, ss) = ML-KEM-768.Encaps(ek_e), ek_e fresh per session (dk_e erased after use)
    th1 = H(label || m1),  th2 = H(th1 || m2 body),  th3 = H(th2 || sig_R)
    prk = HKDF-Extract(salt = th2, ikm = ss [|| X25519(x_I, X_R)])
    K_session, K_cR, K_cI = HKDF-Expand(prk, ...)
    mac_R = HMAC(K_cR, th3),  mac_I = HMAC(K_cI, th3 || mac_R)

Why each piece is there (the Phase 4 failures it answers):

* Session key from the ephemeral KEM secret only, bound to the whole
  transcript. Nothing public gives it (PSRS-D2D), and leaking every long-term
  key later does not open past sessions (PSRS-D2D capture, P2AS-IoAV leak):
  the only decapsulation key, dk_e, no longer exists.
* R verifies Cert_I and sig_I before any key work, and keeps a replay cache of
  (N_I) within the timestamp window (P2AS-IoAV accepted a forged m1).
* sig_R covers ct, so a man in the middle cannot swap the encapsulation, and
  the two MACs give explicit key confirmation in both directions.
* Only short-lived pseudonym certificates identify a vehicle; no static ID or
  password-derived value is ever sent or stored (PSLAP).
* Optional hybrid mode mixes an X25519 secret into the key (as TLS 1.3 hybrid
  key exchange does), so the key stays secret if either ML-KEM or X25519 holds.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qsv2v.attacks.common import AuthenticationError, SimClock
from qsv2v.crypto.rng import DeterministicRNG
from qsv2v.pqc.certs import CRL, CertError, Credential, PseudonymCert, lp, verify_cert
from qsv2v.pqc.kem import MLKEM768
from qsv2v.pqc.sig import SignatureScheme

LABEL = b"PQ-V2V-AKE-v1"
NONCE_LEN = 32
MAX_SKEW = 5  # seconds; V2V clocks are GNSS-synchronised


# -- small primitives ---------------------------------------------------------
def H(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _x25519_pub(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# -- messages -----------------------------------------------------------------
@dataclass(frozen=True)
class Msg1:
    ek: bytes
    x_pub: bytes  # empty unless hybrid
    cert: bytes
    nonce: bytes
    ts: int
    sig: bytes = b""

    def body(self) -> bytes:
        return (
            b"m1" + lp(self.ek) + lp(self.x_pub) + lp(self.cert) + lp(self.nonce)
            + self.ts.to_bytes(8, "big")
        )  # fmt: skip

    def encode(self) -> bytes:
        return self.body() + lp(self.sig)


@dataclass(frozen=True)
class Msg2:
    ct: bytes
    x_pub: bytes
    cert: bytes
    nonce: bytes
    ts: int
    sig: bytes = b""
    mac: bytes = b""

    def body(self) -> bytes:
        return (
            b"m2" + lp(self.ct) + lp(self.x_pub) + lp(self.cert) + lp(self.nonce)
            + self.ts.to_bytes(8, "big")
        )  # fmt: skip

    def encode(self) -> bytes:
        return self.body() + lp(self.sig) + lp(self.mac)


@dataclass(frozen=True)
class Msg3:
    mac: bytes

    def encode(self) -> bytes:
        return b"m3" + lp(self.mac)


# -- parties ------------------------------------------------------------------
@dataclass
class Config:
    hybrid: bool = False
    max_skew: int = MAX_SKEW


@dataclass
class Vehicle:
    """A vehicle: its pseudonym credentials and what it needs to verify peers."""

    credentials: list[Credential]
    scheme: SignatureScheme
    authority_pk: bytes
    authority_scheme: SignatureScheme
    kem: MLKEM768
    rng: DeterministicRNG
    crl: CRL | None = None
    config: Config = field(default_factory=Config)
    seen_nonces: dict[bytes, int] = field(default_factory=dict)

    def credential(self, now: int) -> Credential:
        """The pseudonym valid now (vehicles rotate through their batch)."""
        for c in self.credentials:
            if c.cert.not_before <= now < c.cert.not_after:
                return c
        raise CertError("no valid pseudonym certificate for this time")

    def check_peer(self, cert_bytes: bytes, now: int) -> PseudonymCert:
        try:
            cert = PseudonymCert.decode(cert_bytes)
            verify_cert(cert, self.authority_pk, self.authority_scheme, now, self.crl)
        except (CertError, ValueError) as e:
            raise AuthenticationError(f"peer certificate rejected: {e}") from e
        return cert

    def check_fresh(self, nonce: bytes, ts: int, now: int) -> None:
        if abs(now - ts) > self.config.max_skew:
            raise AuthenticationError("stale timestamp")
        # Forget nonces older than the window; reject any we have seen within it.
        self.seen_nonces = {
            n: t for n, t in self.seen_nonces.items() if now - t <= 2 * self.config.max_skew
        }
        if nonce in self.seen_nonces:
            raise AuthenticationError("replayed nonce")
        self.seen_nonces[nonce] = ts


@dataclass
class InitiatorState:
    m1: Msg1
    dk: bytes | None  # ephemeral decapsulation key: erased in finish()
    x_sk: X25519PrivateKey | None
    th1: bytes


@dataclass
class ResponderState:
    th3: bytes
    k_ci: bytes
    k_session: bytes
    mac_r: bytes
    peer: PseudonymCert


@dataclass(frozen=True)
class SessionResult:
    key: bytes
    peer_pseudonym: bytes
    peer_cert_digest: bytes


def _keys(ss: bytes, x_ss: bytes, th2: bytes) -> tuple[bytes, bytes, bytes]:
    prk = hkdf_extract(th2, ss + x_ss)
    return (
        hkdf_expand(prk, LABEL + b" session key"),
        hkdf_expand(prk, LABEL + b" responder confirm"),
        hkdf_expand(prk, LABEL + b" initiator confirm"),
    )


def initiate(v: Vehicle, clock: SimClock) -> tuple[Msg1, InitiatorState]:
    now = clock.now()
    cred = v.credential(now)
    kp = v.kem.keygen()
    x_sk = X25519PrivateKey.from_private_bytes(v.rng.bytes(32)) if v.config.hybrid else None
    m1 = Msg1(
        ek=kp.public_key,
        x_pub=_x25519_pub(x_sk) if x_sk else b"",
        cert=cred.cert.encode(),
        nonce=v.rng.bytes(NONCE_LEN),
        ts=now,
    )
    sig = v.scheme.sign(cred.secret_key, LABEL + m1.body())
    m1 = Msg1(m1.ek, m1.x_pub, m1.cert, m1.nonce, m1.ts, sig)
    return m1, InitiatorState(m1, kp.secret_key, x_sk, H(LABEL, m1.encode()))


def respond(v: Vehicle, m1: Msg1, clock: SimClock) -> tuple[Msg2, ResponderState]:
    now = clock.now()
    # 1. Authenticate the initiator before any key work.
    peer = v.check_peer(m1.cert, now)
    if not v.scheme.verify(peer.public_key, LABEL + m1.body(), m1.sig):
        raise AuthenticationError("initiator signature invalid")
    v.check_fresh(m1.nonce, m1.ts, now)
    if v.config.hybrid != bool(m1.x_pub):
        raise AuthenticationError("hybrid mode mismatch")
    # 2. Encapsulate to the ephemeral key.
    ct, ss = v.kem.encaps(m1.ek)
    x_ss, x_pub = b"", b""
    if v.config.hybrid:
        x_sk = X25519PrivateKey.from_private_bytes(v.rng.bytes(32))
        x_pub = _x25519_pub(x_sk)
        x_ss = x_sk.exchange(X25519PublicKey.from_public_bytes(m1.x_pub))
    cred = v.credential(now)
    th1 = H(LABEL, m1.encode())
    m2 = Msg2(ct, x_pub, cred.cert.encode(), v.rng.bytes(NONCE_LEN), now)
    th2 = H(th1, m2.body())
    sig = v.scheme.sign(cred.secret_key, LABEL + th2)
    th3 = H(th2, sig)
    k_s, k_cr, k_ci = _keys(ss, x_ss, th2)
    mac_r = mac(k_cr, th3)
    m2 = Msg2(m2.ct, m2.x_pub, m2.cert, m2.nonce, m2.ts, sig, mac_r)
    return m2, ResponderState(th3, k_ci, k_s, mac_r, peer)


def finish(v: Vehicle, st: InitiatorState, m2: Msg2, clock: SimClock) -> tuple[Msg3, SessionResult]:
    now = clock.now()
    if st.dk is None:
        raise AuthenticationError("ephemeral key already used")
    peer = v.check_peer(m2.cert, now)
    if abs(now - m2.ts) > v.config.max_skew:
        raise AuthenticationError("stale timestamp")
    th2 = H(st.th1, m2.body())
    if not v.scheme.verify(peer.public_key, LABEL + th2, m2.sig):
        raise AuthenticationError("responder signature invalid")
    ss = v.kem.decaps(st.dk, m2.ct)
    st.dk = None  # erase the ephemeral decapsulation key: forward secrecy
    x_ss = b""
    if v.config.hybrid:
        if not m2.x_pub:
            raise AuthenticationError("hybrid mode mismatch")
        x_ss = st.x_sk.exchange(X25519PublicKey.from_public_bytes(m2.x_pub))
        st.x_sk = None
    th3 = H(th2, m2.sig)
    k_s, k_cr, k_ci = _keys(ss, x_ss, th2)
    if not hmac.compare_digest(mac(k_cr, th3), m2.mac):
        raise AuthenticationError("responder key confirmation failed")
    m3 = Msg3(mac(k_ci, th3 + m2.mac))
    return m3, SessionResult(k_s, peer.pseudonym, peer.digest)


def confirm(st: ResponderState, m3: Msg3) -> SessionResult:
    if not hmac.compare_digest(mac(st.k_ci, st.th3 + st.mac_r), m3.mac):
        raise AuthenticationError("initiator key confirmation failed")
    return SessionResult(st.k_session, st.peer.pseudonym, st.peer.digest)


@dataclass
class Transcript:
    m1: Msg1
    m2: Msg2
    m3: Msg3
    initiator: SessionResult
    responder: SessionResult

    @property
    def sizes(self) -> dict[str, int]:
        return {
            "m1": len(self.m1.encode()),
            "m2": len(self.m2.encode()),
            "m3": len(self.m3.encode()),
        }


def handshake(i: Vehicle, r: Vehicle, clock: SimClock) -> Transcript:
    m1, st_i = initiate(i, clock)
    m2, st_r = respond(r, m1, clock)
    m3, res_i = finish(i, st_i, m2, clock)
    res_r = confirm(st_r, m3)
    if res_i.key != res_r.key:
        raise AuthenticationError("keys differ")  # cannot happen if all checks passed
    return Transcript(m1, m2, m3, res_i, res_r)


@dataclass
class Network:
    authority: object
    vehicles: list[Vehicle]
    real_ids: list[bytes]
    clock: SimClock


def setup_network(
    n_vehicles: int = 2,
    seed: int = 0,
    hybrid: bool = False,
    n_pseudonyms: int = 3,
    lifetime: int = 300,
    kem_backend: str = "kyber-py",
    sig_backend: str = "dilithium-py",
    sig_alg: str = "ML-DSA-44",
    kem_alg: str = "ML-KEM-768",
    ca_alg: str | None = None,
) -> Network:
    """Authority + enrolled vehicles, each holding ``n_pseudonyms`` consecutive pseudonyms.

    ``sig_alg`` / ``kem_alg`` / ``ca_alg`` select the primitives (the authority
    uses ``sig_alg`` unless ``ca_alg`` is given). With sig_alg="ECDSA-P256" and
    kem_alg="X25519" the same protocol is today's classical design.
    """
    from qsv2v.pqc.certs import Authority, enroll_vehicle
    from qsv2v.pqc.kem import get_kem
    from qsv2v.pqc.sig import get_scheme

    rng = DeterministicRNG(seed)
    clock = SimClock()
    authority = Authority(
        rng.fork("ca"), get_scheme(ca_alg or sig_alg, sig_backend, rng.fork("ca-sig"))
    )
    vehicles, ids = [], []
    for k in range(n_vehicles):
        vr = rng.fork(f"vehicle-{k}")
        scheme = get_scheme(sig_alg, sig_backend, vr.fork("sig"))
        real_id = vr.bytes(17)  # e.g. a VIN; known only to the vehicle and the authority
        creds = enroll_vehicle(authority, real_id, scheme, n_pseudonyms, clock.now(), lifetime)
        vehicles.append(
            Vehicle(
                credentials=creds,
                scheme=scheme,
                authority_pk=authority.public_key,
                authority_scheme=authority.scheme,
                kem=get_kem(kem_alg, kem_backend, vr.fork("kem")),
                rng=vr.fork("protocol"),
                config=Config(hybrid=hybrid),
            )
        )
        ids.append(real_id)
    return Network(authority, vehicles, ids, clock)
