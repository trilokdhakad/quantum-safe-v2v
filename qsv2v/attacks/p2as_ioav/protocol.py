"""P^2AS-IoAV: Shariq et al., IEEE TVT 75(10):24698-24710, 2026 -- AV <-> drone AKA as printed.

Section V-B (registration) and V-C.1 (Fig. 2). Symbols follow Table I.

Registration (TA_i): for each AV_j / drone DR_k it assigns ID, a random primary
key s, and *generates* the Kyber key pair (pr, pu), preloads <pr, ID, s> into
the device, and makes pu public.

msg1 (AV_i -> DR_j):
    (c_i, k_i) <- Encaps(pu_DRj);  sk1* = Enc(s_i, ID_AVi)_{k_i}
    V_1 = h(r_i || k_i || s_i || TS_1);  r_i* = r_i xor h(k_i || V_1 || ID_AVi || TS_1)
    msg1 = {c_i, r_i*, V_1, sk1*, TS_1}
DR_j:  k_i <- Decaps(c_i, pr_DRj); (s_i, ID_AVi) = Dec(sk1*)_{k_i};
       r_i = r_i* xor h(k_i || V_1 || ID_AVi || TS_1);  V_1' = h(r_i || k_i || s_i || TS_1) ?= V_1
msg2 (DR_j -> AV_i):
    (c_j, k_j) <- Encaps(pu_AVi);  sk2* = Enc(s_j, ID_DRj)_{k_j}
    V_2 = h(s_j || k_j || r_j || ID_DRj || TS_2);  r_j* = r_j xor h(k_j || V_2 || ID_DRj || TS_2)
    SK_ji = h(r_i || r_j || s_i || s_j || ID_AVi || ID_DRj || TS_1 || TS_2)
    SKV_ji = h(SK_ji || TS_2)
    msg2 = {r_j*, c_j, sk2*, V_2, SKV_ji, TS_2};  DR_j stores SK_ji.
AV_i:  k_j <- Decaps(c_j, pr_AVi); (s_j, ID_DRj) = Dec(sk2*)_{k_j}; r_j; V_2' ?= V_2;
       SK_ij; SKV_ij ?= SKV_ji; stores SK_ij.

Printed inconsistency: the text gives V_1' = h(r_j || k_j || sk_1 || s_i || TS_1),
which uses values the drone does not have yet and cannot equal V_1. Fig. 2
gives h(r_i || k_i || s_i || TS_1); we use Fig. 2.

Choices where the paper is silent: ML-KEM-768 (FIPS 203, the standardised
Kyber) via :mod:`qsv2v.pqc.kem`; Enc/Dec is AES-256-GCM keyed with the KEM
shared secret; 20-byte identities, 32-byte s and r; SHA-256.
"""

from __future__ import annotations

from dataclasses import dataclass

from qsv2v.attacks.common import AuthenticationError, SimClock, ts_bytes
from qsv2v.crypto import DeterministicRNG, aead_decrypt, aead_encrypt, h, xor_bytes
from qsv2v.pqc.kem import MLKEM768

ID_LEN = 20
S_LEN = 32
DELTA_T = 5


@dataclass
class Device:
    """AV or drone: the preloaded <pr, ID, s> plus its public key."""

    ID: bytes
    s: bytes
    pr: bytes
    pu: bytes


@dataclass
class TA:
    kem: MLKEM768
    directory: dict  # ID -> pu (public)
    escrow: dict  # ID -> pr: the TA generated every private key (Section V-B)


def setup(kem: MLKEM768) -> TA:
    return TA(kem, {}, {})


def register(ta: TA, rng: DeterministicRNG) -> Device:
    kp = ta.kem.keygen()
    dev = Device(rng.bytes(ID_LEN), rng.bytes(S_LEN), kp.secret_key, kp.public_key)
    ta.directory[dev.ID] = dev.pu
    ta.escrow[dev.ID] = dev.pr
    return dev


def _enc(key: bytes, pt: bytes, rng: DeterministicRNG) -> bytes:
    return aead_encrypt(key, pt, rng.bytes(12))


@dataclass(frozen=True)
class Msg1:
    c: bytes
    r_star: bytes
    V1: bytes
    sk_star: bytes
    TS1: int


@dataclass(frozen=True)
class Msg2:
    r_star: bytes
    c: bytes
    sk_star: bytes
    V2: bytes
    SKV: bytes
    TS2: int


@dataclass
class AVState:
    r: bytes
    k: bytes
    TS1: int


def session_key(r_i, r_j, s_i, s_j, id_av, id_dr, ts1, ts2) -> bytes:
    return h(r_i, r_j, s_i, s_j, id_av, id_dr, ts_bytes(ts1), ts_bytes(ts2))


def build_msg1(
    kem: MLKEM768, id_av: bytes, s_av: bytes, pu_dr: bytes, clock: SimClock, rng
) -> tuple[Msg1, AVState]:
    """Step 1. Uses only (ID_AV, s_AV) and the drone's *public* key."""
    r = rng.bytes(32)
    c, k = kem.encaps(pu_dr)
    ts1 = clock.now()
    sk_star = _enc(k, s_av + id_av, rng)
    V1 = h(r, k, s_av, ts_bytes(ts1))
    r_star = xor_bytes(r, h(k, V1, id_av, ts_bytes(ts1)))
    return Msg1(c, r_star, V1, sk_star, ts1), AVState(r, k, ts1)


def av_initiate(kem, av: Device, pu_dr: bytes, clock, rng):
    return build_msg1(kem, av.ID, av.s, pu_dr, clock, rng)


def drone_respond(kem, dr: Device, m: Msg1, directory: dict, clock: SimClock, rng):
    """Step 2. Return (msg2, SK_ji, ID of the vehicle the drone believes it authenticated)."""
    if abs(clock.now() - m.TS1) > DELTA_T:
        raise AuthenticationError("stale timestamp")
    k_i = kem.decaps(dr.pr, m.c)
    try:
        pt = aead_decrypt(k_i, m.sk_star)
    except Exception as e:
        raise AuthenticationError("sk1* decryption failed") from e
    s_i, id_av = pt[:S_LEN], pt[S_LEN:]
    r_i = xor_bytes(m.r_star, h(k_i, m.V1, id_av, ts_bytes(m.TS1)))
    if h(r_i, k_i, s_i, ts_bytes(m.TS1)) != m.V1:
        raise AuthenticationError("V1 check failed")
    if id_av not in directory:
        raise AuthenticationError("unknown vehicle")
    r_j = rng.bytes(32)
    ts2 = clock.now()
    c_j, k_j = kem.encaps(directory[id_av])
    sk2 = _enc(k_j, dr.s + dr.ID, rng)
    V2 = h(dr.s, k_j, r_j, dr.ID, ts_bytes(ts2))
    r_j_star = xor_bytes(r_j, h(k_j, V2, dr.ID, ts_bytes(ts2)))
    sk = session_key(r_i, r_j, s_i, dr.s, id_av, dr.ID, m.TS1, ts2)
    skv = h(sk, ts_bytes(ts2))
    return Msg2(r_j_star, c_j, sk2, V2, skv, ts2), sk, id_av


def av_finish(kem, av: Device, st: AVState, m: Msg2, clock: SimClock) -> bytes:
    if abs(clock.now() - m.TS2) > DELTA_T:
        raise AuthenticationError("stale timestamp")
    k_j = kem.decaps(av.pr, m.c)
    pt = aead_decrypt(k_j, m.sk_star)
    s_j, id_dr = pt[:S_LEN], pt[S_LEN:]
    r_j = xor_bytes(m.r_star, h(k_j, m.V2, id_dr, ts_bytes(m.TS2)))
    if h(s_j, k_j, r_j, id_dr, ts_bytes(m.TS2)) != m.V2:
        raise AuthenticationError("V2 check failed")
    sk = session_key(st.r, r_j, av.s, s_j, av.ID, id_dr, st.TS1, m.TS2)
    if h(sk, ts_bytes(m.TS2)) != m.SKV:
        raise AuthenticationError("SKV check failed")
    return sk


@dataclass
class Session:
    m1: Msg1
    m2: Msg2
    av_id: bytes
    dr_id: bytes
    sk: bytes
    payload_ct: bytes  # data the drone later sends under SK
    payload_pt: bytes  # ground truth


def handshake(kem, av: Device, dr: Device, ta: TA, clock: SimClock, rng, payload: bytes) -> Session:
    m1, st = av_initiate(kem, av, dr.pu, clock, rng)
    clock.advance()
    m2, sk_d, _ = drone_respond(kem, dr, m1, ta.directory, clock, rng)
    clock.advance()
    sk_v = av_finish(kem, av, st, m2, clock)
    assert sk_v == sk_d
    ct = aead_encrypt(sk_v, payload, rng.bytes(12))
    return Session(m1, m2, av.ID, dr.ID, sk_v, ct, payload)
