"""PSLAP: Shariq et al., Computer Networks 261 (2025) 111155 -- implemented as printed.

Section 4 (Figs. 2 and 3). Symbols follow Table 1 of the paper.

Drone registration:  Pr_D, Pu_D = Pr_D.G; <ID_D, Pu_D> public.
AV registration (Fig. 2):
    AV: ID_AV, PWD_AV, R_AV = Pr_AV, a_1;  Pu_AV = R_AV.G;  PID_AV = h(ID_AV || a_1)
    TA: T_RT;  alpha = h(ID_TA || ID_AV || T_RT)   -> AV
    AV: beta = h(PWD) xor a_1;  gamma = alpha xor h(a_1);  delta = h(PID || PWD || alpha || beta)
        OBU stores <beta, gamma, delta>;  TA database keeps <PID_AV, Pu_AV, ID_AV>.
Login (Fig. 3):  a_1' = h(PWD) xor beta;  alpha' = gamma xor h(a_1');  PID' = h(ID || a_1');
    delta' = h(PID' || PWD || alpha' || gamma)  ?= delta
msg1 (AV -> D):  A = Pr_AV.Pu_D;  X = a_2.Pu_D;  Y = a_2.G;  TID = h(X) xor PID;
    m0 = h(PID || X_x || A_y || T1);  m1 = m0 xor alpha;  m2 = h(alpha || X_y || A_x || ID_D || T1)
msg2 (D -> AV):  X' = Pr_D.Y;  A = Pr_D.Pu_AV;  ...;  W = b_1.Y;  Z = b_1.G;
    m3 = h(ID_D || W_x || A_y || T2);  A2 = h(PID || W_x);  m4 = m3 xor A2;
    m5 = h(A2 || W_y || A_x || PID || T2);  SK = h(W || alpha || A);  VER = h(SK || X'_x)

Printed inconsistencies, each reproducible with a flag:
* msg1 contents. Section 4.3 and the cost analysis (Section 6.3) send
  msg1 = <Y, m1, m2, PID_AV, T1> -- the static pseudo-identity in clear.
  Fig. 3 and Proposition 2 send TID_AV = h(X) xor PID_AV instead.
  ``variant="text"`` / ``variant="figure"``.
* Registration defines delta with beta, login recomputes it with gamma, so the
  printed login check can never pass. ``login_as_printed=True`` reproduces
  that; the default recomputes delta with beta (the consistent reading).

Choices where the paper is silent: P-256, SHA-256, 20-byte identities,
32-byte random a_1 / hash-sized XOR operands, '||' over fixed-width encodings.
The drone looks up Pu_AV in the TA database using the recovered PID (the paper
uses Pu_AV without saying how the drone obtains it).
"""

from __future__ import annotations

from dataclasses import dataclass

from qsv2v.attacks.common import AuthenticationError, SimClock, ts_bytes
from qsv2v.crypto import DeterministicRNG, G, Q, h, point_bytes, x_bytes, xor_bytes, y_bytes

ID_LEN = 20
DELTA_T = 5


@dataclass
class Drone:
    ID: bytes
    Pr: int
    Pu: object


@dataclass
class OBU:
    """The tamper-proof OBU contents, exactly as stored in Fig. 2."""

    beta: bytes
    gamma: bytes
    delta: bytes


@dataclass
class Vehicle:
    ID: bytes
    PWD: bytes
    Pr: int  # R_AV; the paper does not say where it is kept, only that AV uses it
    Pu: object
    obu: OBU
    # Ground truth, kept for checking attacks (not part of the OBU):
    a1: bytes
    alpha: bytes
    PID: bytes


@dataclass
class TA:
    ID_TA: bytes
    database: dict  # PID -> (Pu_AV, ID_AV)


def setup(rng: DeterministicRNG) -> TA:
    return TA(rng.bytes(ID_LEN), {})


def register_drone(rng: DeterministicRNG) -> Drone:
    pr = rng.scalar(Q)
    return Drone(rng.bytes(ID_LEN), pr, pr * G)


def register_vehicle(
    ta: TA, rng: DeterministicRNG, password: bytes, clock: SimClock, id_av: bytes | None = None
) -> Vehicle:
    id_av = id_av or rng.bytes(ID_LEN)
    pr = rng.scalar(Q)
    a1 = rng.bytes(32)
    pid = h(id_av, a1)
    t_rt = clock.now()
    alpha = h(ta.ID_TA, id_av, ts_bytes(t_rt))
    beta = xor_bytes(h(password), a1)
    gamma = xor_bytes(alpha, h(a1))
    delta = h(pid, password, alpha, beta)
    ta.database[pid] = (pr * G, id_av)
    return Vehicle(id_av, password, pr, pr * G, OBU(beta, gamma, delta), a1, alpha, pid)


def login(id_av: bytes, password: bytes, obu: OBU, as_printed: bool = False):
    """Return (a1, alpha, PID) on success; raise on failure."""
    a1 = xor_bytes(h(password), obu.beta)
    alpha = xor_bytes(obu.gamma, h(a1))
    pid = h(id_av, a1)
    last = obu.gamma if as_printed else obu.beta
    if h(pid, password, alpha, last) != obu.delta:
        raise AuthenticationError("login failed: delta mismatch")
    return a1, alpha, pid


@dataclass(frozen=True)
class Msg1:
    Y: object
    m1: bytes
    m2: bytes
    ident: bytes  # PID_AV (text variant) or TID_AV (figure variant)
    T1: int


@dataclass(frozen=True)
class Msg2:
    Z: object
    m4: bytes
    m5: bytes
    ID_D: bytes
    VER: bytes
    T2: int


@dataclass
class AVState:
    a2: int
    X: object
    A: object
    alpha: bytes
    PID: bytes


def av_initiate(
    av: Vehicle,
    drone_id: bytes,
    drone_pu,
    clock: SimClock,
    rng: DeterministicRNG,
    variant: str = "text",
    login_as_printed: bool = False,
):
    _, alpha, pid = login(av.ID, av.PWD, av.obu, login_as_printed)
    A = av.Pr * drone_pu
    a2 = rng.scalar(Q)
    X = a2 * drone_pu
    Y = a2 * G
    T1 = clock.now()
    m0 = h(pid, x_bytes(X), y_bytes(A), ts_bytes(T1))
    m1 = xor_bytes(m0, alpha)
    m2 = h(alpha, y_bytes(X), x_bytes(A), drone_id, ts_bytes(T1))
    if variant == "text":
        ident = pid
    elif variant == "figure":
        ident = xor_bytes(h(point_bytes(X)), pid)
    else:
        raise ValueError("variant must be 'text' or 'figure'")
    return Msg1(Y, m1, m2, ident, T1), AVState(a2, X, A, alpha, pid)


def drone_respond(
    drone: Drone,
    msg: Msg1,
    ta_db: dict,
    clock: SimClock,
    rng: DeterministicRNG,
    variant: str = "text",
):
    """Return (msg2, SK, PID of the authenticated vehicle)."""
    if abs(clock.now() - msg.T1) > DELTA_T:
        raise AuthenticationError("stale timestamp")
    Xp = drone.Pr * msg.Y
    pid = msg.ident if variant == "text" else xor_bytes(h(point_bytes(Xp)), msg.ident)
    if pid not in ta_db:
        raise AuthenticationError("unknown pseudo-identity")
    pu_av, _ = ta_db[pid]
    A = drone.Pr * pu_av
    m0 = h(pid, x_bytes(Xp), y_bytes(A), ts_bytes(msg.T1))
    alpha = xor_bytes(m0, msg.m1)
    if h(alpha, y_bytes(Xp), x_bytes(A), drone.ID, ts_bytes(msg.T1)) != msg.m2:
        raise AuthenticationError("m2 check failed")
    b1 = rng.scalar(Q)
    W = b1 * msg.Y
    Z = b1 * G
    T2 = clock.now()
    m3 = h(drone.ID, x_bytes(W), y_bytes(A), ts_bytes(T2))
    A2 = h(pid, x_bytes(W))
    m4 = xor_bytes(m3, A2)
    m5 = h(A2, y_bytes(W), x_bytes(A), pid, ts_bytes(T2))
    sk = h(point_bytes(W), alpha, point_bytes(A))
    ver = h(sk, x_bytes(Xp))
    return Msg2(Z, m4, m5, drone.ID, ver, T2), sk, pid


def av_finish(st: AVState, msg: Msg2, clock: SimClock) -> bytes:
    if abs(clock.now() - msg.T2) > DELTA_T:
        raise AuthenticationError("stale timestamp")
    W = st.a2 * msg.Z
    m3 = h(msg.ID_D, x_bytes(W), y_bytes(st.A), ts_bytes(msg.T2))
    A2 = xor_bytes(m3, msg.m4)
    if A2 != h(st.PID, x_bytes(W)):
        raise AuthenticationError("A2 check failed")
    if msg.m5 != h(A2, y_bytes(W), x_bytes(st.A), st.PID, ts_bytes(msg.T2)):
        raise AuthenticationError("m5 check failed")
    sk = h(point_bytes(W), st.alpha, point_bytes(st.A))
    if msg.VER != h(sk, x_bytes(st.X)):
        raise AuthenticationError("VER check failed")
    return sk


@dataclass
class Session:
    msg1: Msg1
    msg2: Msg2
    vehicle_id: bytes  # ground truth, for scoring attacks
    drone_id: bytes
    sk: bytes


def handshake(
    av: Vehicle, drone: Drone, ta: TA, clock: SimClock, rng, variant: str = "text"
) -> Session:
    m1, st = av_initiate(av, drone.ID, drone.Pu, clock, rng, variant)
    clock.advance()
    m2, sk_d, _ = drone_respond(drone, m1, ta.database, clock, rng, variant)
    clock.advance()
    sk_v = av_finish(st, m2, clock)
    assert sk_v == sk_d
    return Session(m1, m2, av.ID, drone.ID, sk_v)
