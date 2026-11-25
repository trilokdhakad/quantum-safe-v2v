"""PSRS-D2D: Shariq et al., IEEE TMC 25(1):1445-1454, 2026 -- implemented as printed.

Section V (Fig. 2). Symbols follow Table II of the paper.

Initialization (TA):
    MK_TA, MP_TA = MK_TA.G ;  Pr_TA, Pub_TA = Pr_TA.G ;  ID_TA
Registration of entity alpha:
    Pr_a, Pub_a = Pr_a.G
    Cert_a = Pr_TA + MK_TA + h(Pub_a || ID_TA || ID_a || Pub_TA) * Pr_TA   (mod q)
    drone memory: {ID_a, ID_TA, Pr_a, Pub_a, Pub_TA, Cert_a, MP_TA}
Message 1 (D_i -> D_j):
    X_i = a_i.G, Y_i = a_i.Pub_j, ADC_i = a_i + Cert_i, IDbar_i = X_i xor ID_i,
    U_i = h(ID_i || X_i || ADC_i || T_i);   m1 = <IDbar_i, Y_i, ADC_i, U_i, T_i>
D_j:  X_i' = Y_i.Pr_j^-1, ID_i' = IDbar_i xor X_i',
      ADC_i.G =? X_i + h(Pub || ID_TA || ID || Pub_TA).Pub_TA + Pub_TA + MP_TA,
      U_i =? h(ID_i' || X_i' || ADC_i || T_i)
Message 2 (D_j -> D_i):
    X_j = a_j.G, Y_j = a_j.Pub_i, ADC_j = a_j + Cert_j, IDbar_j = X_j xor ID_j,
    SK_ji = h(X_i || X_j || ID_i || ID_j || T_i || T_j),
    SKV_ji = h(SK_ji || X_i || X_j || T_j);   m2 = <IDbar_j, Y_j, ADC_j, SKV_ji, T_j>
D_i:  X_j' = Y_j.Pr_i^-1, ID_j' = IDbar_j xor X_j', certificate check, SK_ij, SKV check.

Implementation choices where the paper is silent (none affects any attack):
* curve P-256; identities are 160 bits (Section VII-B) and "X xor ID" XORs
  the identity with the first 20 bytes of X's x-coordinate; h is SHA-256; hash
  values used as scalars are reduced mod q; '||' concatenates fixed-width
  encodings; timestamps are 32-bit.
* The verifier needs Pub_i of the peer; the paper never says how it obtains
  it. We give drones the public directory {ID -> Pub} that the TA publishes.

Printed inconsistency: step 2 verifies D_i's certificate with
h(Pub_j || ID_TA || ID_j || Pub_TA) -- the *verifier's own* values, which can
never match Cert_i. ``as_printed=True`` reproduces that (honest runs fail);
the default uses the only consistent reading, h(Pub_i || ID_TA || ID_i || Pub_TA).
"""

from __future__ import annotations

from dataclasses import dataclass

from qsv2v.attacks.common import AuthenticationError, SimClock, ts_bytes
from qsv2v.crypto import DeterministicRNG, G, Q, h, hash_to_scalar, point_bytes, x_bytes, xor_bytes

ID_LEN = 20  # 160-bit identities, as in the paper's cost analysis
DELTA_T = 5  # seconds


def mask(point) -> bytes:
    """The ID-sized slice of a point used for IDbar = X xor ID."""
    return x_bytes(point)[:ID_LEN]


def scalar_bytes(k: int) -> bytes:
    return k.to_bytes(32, "big")


@dataclass(frozen=True)
class PublicParams:
    ID_TA: bytes
    Pub_TA: object
    MP_TA: object


@dataclass
class TrustedAuthority:
    ID_TA: bytes
    MK_TA: int
    Pr_TA: int

    @property
    def public(self) -> PublicParams:
        return PublicParams(self.ID_TA, self.Pr_TA * G, self.MK_TA * G)


@dataclass
class DroneMemory:
    """Exactly the values the paper stores in a drone's memory."""

    ID: bytes
    ID_TA: bytes
    Pr: int
    Pub: object
    Pub_TA: object
    Cert: int
    MP_TA: object


def cert_hash(pub, id_: bytes, pp: PublicParams) -> int:
    return hash_to_scalar(point_bytes(pub), pp.ID_TA, id_, point_bytes(pp.Pub_TA))


def cert_public_point(pub, id_: bytes, pp: PublicParams):
    """Cert.G, computable from public values: Pub_TA + MP_TA + h(...).Pub_TA."""
    return pp.Pub_TA + pp.MP_TA + cert_hash(pub, id_, pp) * pp.Pub_TA


def setup(rng: DeterministicRNG) -> TrustedAuthority:
    return TrustedAuthority(ID_TA=rng.bytes(ID_LEN), MK_TA=rng.scalar(Q), Pr_TA=rng.scalar(Q))


def issue_certificate(Pr_TA: int, MK_TA: int, pub, id_: bytes, pp: PublicParams) -> int:
    return (Pr_TA + MK_TA + cert_hash(pub, id_, pp) * Pr_TA) % Q


def register(ta: TrustedAuthority, rng: DeterministicRNG, id_: bytes | None = None) -> DroneMemory:
    pp = ta.public
    id_ = id_ or rng.bytes(ID_LEN)
    pr = rng.scalar(Q)
    pub = pr * G
    cert = issue_certificate(ta.Pr_TA, ta.MK_TA, pub, id_, pp)
    return DroneMemory(id_, pp.ID_TA, pr, pub, pp.Pub_TA, cert, pp.MP_TA)


@dataclass(frozen=True)
class Msg1:
    IDbar: bytes
    Y: object
    ADC: int
    U: bytes
    T: int


@dataclass(frozen=True)
class Msg2:
    IDbar: bytes
    Y: object
    ADC: int
    SKV: bytes
    T: int


@dataclass
class InitiatorState:
    a: int
    X: object
    T: int
    peer_pub: object


def session_key(X_i, X_j, ID_i: bytes, ID_j: bytes, T_i: int, T_j: int) -> bytes:
    return h(point_bytes(X_i), point_bytes(X_j), ID_i, ID_j, ts_bytes(T_i), ts_bytes(T_j))


def session_key_verifier(sk: bytes, X_i, X_j, T_j: int) -> bytes:
    return h(sk, point_bytes(X_i), point_bytes(X_j), ts_bytes(T_j))


def _check_cert(adc: int, X, peer_pub, peer_id, verifier: DroneMemory, as_printed: bool) -> None:
    pp = PublicParams(verifier.ID_TA, verifier.Pub_TA, verifier.MP_TA)
    if as_printed:  # h(Pub_j || ID_TA || ID_j || Pub_TA): the verifier's own values
        rhs = X + cert_public_point(verifier.Pub, verifier.ID, pp)
    else:
        rhs = X + cert_public_point(peer_pub, peer_id, pp)
    if adc * G != rhs:
        raise AuthenticationError("certificate check ADC.G failed")


def initiate(mem: DroneMemory, peer_pub, clock: SimClock, rng: DeterministicRNG):
    a = rng.scalar(Q)
    T = clock.now()
    X = a * G
    Y = a * peer_pub
    adc = (a + mem.Cert) % Q
    idbar = xor_bytes(mask(X), mem.ID)
    U = h(mem.ID, point_bytes(X), scalar_bytes(adc), ts_bytes(T))
    return Msg1(idbar, Y, adc, U, T), InitiatorState(a, X, T, peer_pub)


def respond(
    mem: DroneMemory,
    m1: Msg1,
    directory: dict[bytes, object],
    clock: SimClock,
    rng: DeterministicRNG,
    as_printed: bool = False,
) -> tuple[Msg2, bytes, bytes]:
    """Return (message 2, session key, authenticated peer identity)."""
    if abs(clock.now() - m1.T) > DELTA_T:
        raise AuthenticationError("stale timestamp")
    X_i = pow(mem.Pr, -1, Q) * m1.Y
    ID_i = xor_bytes(m1.IDbar, mask(X_i))
    if ID_i not in directory:
        raise AuthenticationError("unknown identity")
    _check_cert(m1.ADC, X_i, directory[ID_i], ID_i, mem, as_printed)
    if m1.U != h(ID_i, point_bytes(X_i), scalar_bytes(m1.ADC), ts_bytes(m1.T)):
        raise AuthenticationError("U_i check failed")
    a = rng.scalar(Q)
    T = clock.now()
    X_j = a * G
    Y_j = a * directory[ID_i]
    adc = (a + mem.Cert) % Q
    idbar = xor_bytes(mask(X_j), mem.ID)
    sk = session_key(X_i, X_j, ID_i, mem.ID, m1.T, T)
    skv = session_key_verifier(sk, X_i, X_j, T)
    return Msg2(idbar, Y_j, adc, skv, T), sk, ID_i


def finish(
    mem: DroneMemory,
    st: InitiatorState,
    m2: Msg2,
    directory: dict[bytes, object],
    clock: SimClock,
    as_printed: bool = False,
) -> tuple[bytes, bytes]:
    """Return (session key, authenticated peer identity)."""
    if abs(clock.now() - m2.T) > DELTA_T:
        raise AuthenticationError("stale timestamp")
    X_j = pow(mem.Pr, -1, Q) * m2.Y
    ID_j = xor_bytes(m2.IDbar, mask(X_j))
    if ID_j not in directory:
        raise AuthenticationError("unknown identity")
    _check_cert(m2.ADC, X_j, directory[ID_j], ID_j, mem, as_printed)
    sk = session_key(st.X, X_j, mem.ID, ID_j, st.T, m2.T)
    if m2.SKV != session_key_verifier(sk, st.X, X_j, m2.T):
        raise AuthenticationError("SKV check failed")
    return sk, ID_j


@dataclass
class Session:
    """One completed handshake, with ground truth kept for checking attacks."""

    m1: Msg1
    m2: Msg2
    initiator: bytes
    responder: bytes
    sk: bytes


def handshake(
    di: DroneMemory,
    dj: DroneMemory,
    directory: dict[bytes, object],
    clock: SimClock,
    rng: DeterministicRNG,
    as_printed: bool = False,
) -> Session:
    m1, st = initiate(di, dj.Pub, clock, rng)
    clock.advance()
    m2, sk_j, peer = respond(dj, m1, directory, clock, rng, as_printed)
    clock.advance()
    sk_i, _ = finish(di, st, m2, directory, clock, as_printed)
    assert sk_i == sk_j and peer == di.ID
    return Session(m1, m2, di.ID, dj.ID, sk_i)


@dataclass
class Network:
    ta: TrustedAuthority
    drones: list[DroneMemory]

    @property
    def directory(self) -> dict[bytes, object]:
        return {d.ID: d.Pub for d in self.drones}


def build_network(n_drones: int, rng: DeterministicRNG) -> Network:
    ta = setup(rng)
    return Network(ta, [register(ta, rng) for _ in range(n_drones)])
