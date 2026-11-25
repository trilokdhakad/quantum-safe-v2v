"""Attacks on P^2AS-IoAV (Shariq et al., IEEE TVT 2026).

1. Forged message 1 is accepted. Every value the drone checks in msg1 is
   derived from k_i -- which anyone creates with Encaps(pu_DRj), pu_DRj being
   public -- or from (s_i, ID_AV), which the drone reads out of sk1* itself and
   never compares with anything it stores. So an attacker with no credentials
   builds a msg1 that passes every check, for any registered vehicle ID, and the
   drone stores a session with that vehicle. (Prop. 8 states the attacker
   "cannot recompute k_i without knowing pr_DRj, although s/he knows c_i";
   that ignores that the attacker chooses c_i.) The attacker does not learn the
   resulting SK_ji: that needs k_j, encapsulated to the real vehicle.

2. No forward secrecy. All KEM keys are static, and SK = h(r_i||r_j||s_i||s_j||...)
   is protected only by them: r_i, s_i, ID_AV under k_i (to pr_DR), and r_j, s_j
   under k_j (to pr_AV). If the two parties' long-term private keys leak later
   -- or the TA's copies, since the TA generated them -- every recorded past
   session key and the data sent under it are recovered. (Prop. 9 claims the
   opposite.) The demo also shows what one leaked key gives on its own: the
   drone's key alone de-anonymises past vehicles (ID_AV, s_i) but does not
   yield SK, because r_j stays hidden under k_j.
"""

from __future__ import annotations

from qsv2v.attacks.common import AttackResult, SimClock, Timer
from qsv2v.attacks.p2as_ioav import protocol as P
from qsv2v.crypto import DeterministicRNG, aead_decrypt, h, xor_bytes
from qsv2v.pqc.kem import MLKEM768

PAPER = "P2AS-IoAV (IEEE TVT 2026)"


def make_network(seed: int, n_av: int, n_dr: int, kem_backend: str = "kyber-py"):
    rng = DeterministicRNG(seed)
    kem = MLKEM768(kem_backend, rng=rng.fork("kem"))
    ta = P.setup(kem)
    avs = [P.register(ta, rng) for _ in range(n_av)]
    drs = [P.register(ta, rng) for _ in range(n_dr)]
    return rng, kem, ta, avs, drs


# --------------------------------------------------------------------------
# Attack 1: forged message 1
# --------------------------------------------------------------------------
def forge_msg1(kem: MLKEM768, claimed_id: bytes, pu_dr: bytes, clock, rng) -> P.Msg1:
    """Attacker's msg1: public key of the drone + a claimed ID; s is made up."""
    fake_s = rng.bytes(P.S_LEN)
    m1, _ = P.build_msg1(kem, claimed_id, fake_s, pu_dr, clock, rng)
    return m1


def demo_forged_msg1(seed: int = 6, kem_backend: str = "kyber-py") -> AttackResult:
    rng, kem, ta, avs, drs = make_network(seed, 3, 2, kem_backend)
    victim, drone = avs[1], drs[0]
    clock = SimClock()
    res = AttackResult(
        PAPER,
        "Forged message 1 accepted by the drone (vehicle impersonation)",
        "Prop. 1 (mutual authentication), Prop. 8 (resists impersonation)",
        "no credentials; knows the drone's public key and a registered vehicle ID",
    )
    with Timer() as t:
        attacker_rng = DeterministicRNG(f"attacker-{seed}")
        m1 = forge_msg1(kem, victim.ID, drone.pu, clock, attacker_rng)
        clock.advance()
        _, drone_sk, accepted = P.drone_respond(kem, drone, m1, ta.directory, clock, rng)
    res.elapsed_s = t.elapsed
    res.recovered = {"drone accepted msg1 as vehicle": accepted.hex()}
    res.expected = {"drone accepted msg1 as vehicle": victim.ID.hex()}
    res.notes.append(
        "drone stored a session key for the victim vehicle; the forger used a made-up s_i "
        "and never touched the victim's credentials"
    )
    res.notes.append(
        "the forger cannot compute that session key (needs k_j, encapsulated to the real "
        "vehicle): this is acceptance of a forged message, not key recovery"
    )
    return res


# --------------------------------------------------------------------------
# Attack 2: past-session decryption after long-term key leak
# --------------------------------------------------------------------------
def unwrap_msg1(kem, pr_dr: bytes, m1: P.Msg1):
    k_i = kem.decaps(pr_dr, m1.c)
    pt = aead_decrypt(k_i, m1.sk_star)
    s_i, id_av = pt[: P.S_LEN], pt[P.S_LEN :]
    r_i = xor_bytes(m1.r_star, h(k_i, m1.V1, id_av, P.ts_bytes(m1.TS1)))
    return s_i, id_av, r_i


def unwrap_msg2(kem, pr_av: bytes, m2: P.Msg2):
    k_j = kem.decaps(pr_av, m2.c)
    pt = aead_decrypt(k_j, m2.sk_star)
    s_j, id_dr = pt[: P.S_LEN], pt[P.S_LEN :]
    r_j = xor_bytes(m2.r_star, h(k_j, m2.V2, id_dr, P.ts_bytes(m2.TS2)))
    return s_j, id_dr, r_j


def recover_past_session(kem, pr_dr: bytes, pr_av: bytes, sess: P.Session):
    s_i, id_av, r_i = unwrap_msg1(kem, pr_dr, sess.m1)
    s_j, id_dr, r_j = unwrap_msg2(kem, pr_av, sess.m2)
    sk = P.session_key(r_i, r_j, s_i, s_j, id_av, id_dr, sess.m1.TS1, sess.m2.TS2)
    return sk, aead_decrypt(sk, sess.payload_ct)


def demo_past_session_decryption(
    seed: int = 7, n_sessions: int = 3, kem_backend: str = "kyber-py"
) -> AttackResult:
    rng, kem, ta, avs, drs = make_network(seed, 2, 2, kem_backend)
    av, dr = avs[0], drs[0]
    clock = SimClock()
    recorded = []
    for i in range(n_sessions):
        payload = b"aggregated AV telemetry, batch %d: lat 25.2048 lon 55.2708" % i
        recorded.append(P.handshake(kem, av, dr, ta, clock, rng, payload))
        clock.advance(600)

    res = AttackResult(
        PAPER,
        "Past-session decryption after long-term key leak (no forward secrecy)",
        "Prop. 9 (perfect forward secrecy)",
        "recorded transcripts; later obtains pr_DR and pr_AV (or the TA's copies)",
    )
    with Timer() as t:
        # Later: the static private keys leak (here: the TA's escrow, Section V-B).
        pr_dr, pr_av = ta.escrow[dr.ID], ta.escrow[av.ID]
        out = [recover_past_session(kem, pr_dr, pr_av, s) for s in recorded]
        # One key alone: drone key de-anonymises but does not give SK.
        s_i, id_av, _ = unwrap_msg1(kem, dr.pr, recorded[0].m1)
    res.elapsed_s = t.elapsed
    for i, (s, (sk, pt)) in enumerate(zip(recorded, out, strict=True)):
        res.recovered[f"session {i + 1} key"] = sk.hex()
        res.expected[f"session {i + 1} key"] = s.sk.hex()
        res.recovered[f"session {i + 1} plaintext"] = pt.decode()
        res.expected[f"session {i + 1} plaintext"] = s.payload_pt.decode()
    res.notes.append(
        "drone key alone recovers past vehicle ID_AV and s_i "
        f"(ID match: {id_av == av.ID}, s match: {s_i == av.s}); SK also needs pr_AV"
    )
    return res


def run_all(seed: int = 0, kem_backend: str = "kyber-py") -> list[AttackResult]:
    return [
        demo_forged_msg1(seed + 6, kem_backend),
        demo_past_session_decryption(seed + 7, kem_backend=kem_backend),
    ]


if __name__ == "__main__":
    for r in run_all():
        print(r.report(), end="\n\n")
