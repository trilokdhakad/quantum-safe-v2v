"""Attacks on PSRS-D2D (Shariq et al., IEEE TMC 2026).

Root causes, from the equations in Section V:

1. ADC = a + Cert and Cert.G is public (Pub_TA + MP_TA + h(Pub||ID_TA||ID||Pub_TA).Pub_TA).
   So X = a.G = ADC.G - Cert.G is computable by anyone who knows the sender's
   (ID, Pub). The session key h(X_i||X_j||ID_i||ID_j||T_i||T_j) contains no
   Diffie-Hellman secret a_i.a_j.G, so a passive eavesdropper computes it.
2. A captured drone holds Pr and Cert. Pr unmasks the peer's X from Y; Cert
   unmasks the drone's own a = ADC - Cert. Every past session key follows.
3. Cert is affine in the TA's two secrets with a public coefficient h_a:
   Cert_a = (Pr_TA + MK_TA) + h_a.Pr_TA. Two captured certificates give two
   linear equations mod q in two unknowns.
"""

from __future__ import annotations

from qsv2v.attacks.common import AttackResult, SimClock, Timer
from qsv2v.attacks.psrs_d2d import protocol as P
from qsv2v.crypto import DeterministicRNG, G, Q, xor_bytes

PAPER = "PSRS-D2D (IEEE TMC 2026)"


# --------------------------------------------------------------------------
# Attack 1: passive session-key recovery (and de-anonymisation)
# --------------------------------------------------------------------------
def unmask_sender(adc: int, idbar: bytes, directory: dict, pp: P.PublicParams):
    """Find which registered drone sent (ADC, IDbar), and its ephemeral X.

    For each public (ID, Pub): X_cand = ADC.G - Cert.G. The right candidate
    satisfies IDbar xor X_cand == ID.
    """
    adcG = adc * G
    for id_, pub in directory.items():
        X = adcG + (-P.cert_public_point(pub, id_, pp))
        if xor_bytes(idbar, P.mask(X)) == id_:
            return id_, X
    return None, None


def passive_session_key_recovery(
    session: P.Session, directory: dict, pp: P.PublicParams
) -> dict[str, bytes]:
    """Eavesdropper with public parameters + public key directory only."""
    id_i, X_i = unmask_sender(session.m1.ADC, session.m1.IDbar, directory, pp)
    id_j, X_j = unmask_sender(session.m2.ADC, session.m2.IDbar, directory, pp)
    sk = P.session_key(X_i, X_j, id_i, id_j, session.m1.T, session.m2.T)
    # The transcript lets the attacker confirm the guess: SKV_ji is public.
    confirmed = session.m2.SKV == P.session_key_verifier(sk, X_i, X_j, session.m2.T)
    return {"ID_i": id_i, "ID_j": id_j, "SK": sk, "confirmed": confirmed}


def demo_session_key_recovery(seed: int = 1, n_drones: int = 20) -> AttackResult:
    rng = DeterministicRNG(seed)
    net = P.build_network(n_drones, rng)
    clock = SimClock()
    di, dj = net.drones[3], net.drones[11]
    sess = P.handshake(di, dj, net.directory, clock, rng)

    res = AttackResult(
        PAPER,
        "Passive session-key recovery and de-anonymisation",
        "Prop. 2 (anonymity), Prop. 5 (resists session key computation)",
        "eavesdropper; knows only public parameters and the public key directory",
    )
    with Timer() as t:
        out = passive_session_key_recovery(sess, net.directory, net.ta.public)
    res.elapsed_s = t.elapsed
    res.recovered = {
        "initiator ID": out["ID_i"].hex(),
        "responder ID": out["ID_j"].hex(),
        "session key": out["SK"].hex(),
    }
    res.expected = {
        "initiator ID": di.ID.hex(),
        "responder ID": dj.ID.hex(),
        "session key": sess.sk.hex(),
    }
    res.notes.append(
        f"guess self-confirmed against public SKV_ji: {out['confirmed']}; "
        f"searched {n_drones} directory entries"
    )
    return res


# --------------------------------------------------------------------------
# Attack 2: forward secrecy broken by capturing one drone
# --------------------------------------------------------------------------
def recover_past_session(captured: P.DroneMemory, session: P.Session) -> bytes:
    """Past session key from a captured drone's memory {Pr, Cert, ID, ...}."""
    inv = pow(captured.Pr, -1, Q)
    m1, m2 = session.m1, session.m2
    if xor_bytes(m2.IDbar, P.mask(((m2.ADC - captured.Cert) % Q) * G)) == captured.ID:
        # Captured drone was the responder: own a_j = ADC_j - Cert_j; peer X_i = Y_i.Pr^-1.
        X_j = ((m2.ADC - captured.Cert) % Q) * G
        X_i = inv * m1.Y
        id_i, id_j = xor_bytes(m1.IDbar, P.mask(X_i)), captured.ID
    else:
        # Captured drone was the initiator: own a_i = ADC_i - Cert_i; peer X_j = Y_j.Pr^-1.
        X_i = ((m1.ADC - captured.Cert) % Q) * G
        X_j = inv * m2.Y
        id_i, id_j = captured.ID, xor_bytes(m2.IDbar, P.mask(X_j))
    return P.session_key(X_i, X_j, id_i, id_j, m1.T, m2.T)


def demo_forward_secrecy(seed: int = 2, n_drones: int = 10, n_sessions: int = 6) -> AttackResult:
    rng = DeterministicRNG(seed)
    net = P.build_network(n_drones, rng)
    clock = SimClock()
    victim = net.drones[0]
    recorded = []
    for k in range(n_sessions):
        peer = net.drones[1 + k % (n_drones - 1)]
        pair = (victim, peer) if k % 2 == 0 else (peer, victim)  # both roles
        recorded.append(P.handshake(*pair, net.directory, clock, rng))
        clock.advance(60)

    res = AttackResult(
        PAPER,
        "Forward secrecy broken by one drone capture",
        "Prop. 4 (forward secrecy), Prop. 11 (resists drone capture)",
        "recorded past transcripts, later captures the victim drone's memory",
    )
    with Timer() as t:
        keys = [recover_past_session(victim, s) for s in recorded]
    res.elapsed_s = t.elapsed
    for i, (s, k) in enumerate(zip(recorded, keys, strict=True)):
        role = "initiator" if s.initiator == victim.ID else "responder"
        res.recovered[f"past session {i + 1} key ({role})"] = k.hex()
        res.expected[f"past session {i + 1} key ({role})"] = s.sk.hex()
    return res


# --------------------------------------------------------------------------
# Attack 3: master-key extraction from two captured certificates
# --------------------------------------------------------------------------
def extract_master_keys(m1: P.DroneMemory, m2: P.DroneMemory) -> tuple[int, int]:
    """Solve Cert_a = (Pr_TA + MK_TA) + h_a.Pr_TA for (Pr_TA, MK_TA)."""
    pp = P.PublicParams(m1.ID_TA, m1.Pub_TA, m1.MP_TA)
    h1 = P.cert_hash(m1.Pub, m1.ID, pp)
    h2 = P.cert_hash(m2.Pub, m2.ID, pp)
    pr_ta = ((m1.Cert - m2.Cert) * pow(h1 - h2, -1, Q)) % Q
    mk_ta = (m1.Cert - pr_ta * (1 + h1)) % Q
    return pr_ta, mk_ta


def impersonate(
    pr_ta: int, mk_ta: int, victim_id: bytes, victim_pub, pp: P.PublicParams, rng
) -> P.DroneMemory:
    """Forge a memory image for a drone the attacker never captured.

    The attacker re-issues the victim's certificate with the stolen master
    keys. It does not know the victim's Pr; a random stand-in is used and,
    as shown in the demo, is never needed to finish a handshake as initiator.
    """
    cert = P.issue_certificate(pr_ta, mk_ta, victim_pub, victim_id, pp)
    return P.DroneMemory(victim_id, pp.ID_TA, rng.scalar(Q), victim_pub, pp.Pub_TA, cert, pp.MP_TA)


def demo_master_key_extraction(seed: int = 3, n_drones: int = 8) -> AttackResult:
    rng = DeterministicRNG(seed)
    net = P.build_network(n_drones, rng)
    pp = net.ta.public
    cap1, cap2 = net.drones[0], net.drones[1]

    res = AttackResult(
        PAPER,
        "Master-key extraction from two captured drones, then impersonation",
        "Prop. 11 (MK_TA and Pr_TA cannot be extracted), Prop. 10 (impersonation)",
        "physically captures two drones (memory read-out); public parameters",
    )
    with Timer() as t:
        pr_ta, mk_ta = extract_master_keys(cap1, cap2)
        consistent = pr_ta * G == pp.Pub_TA and mk_ta * G == pp.MP_TA

        # Impersonate a third, never-captured drone to an honest drone.
        victim, honest = net.drones[5], net.drones[6]
        fake = impersonate(pr_ta, mk_ta, victim.ID, victim.Pub, pp, rng)
        clock = SimClock()
        m1, st = P.initiate(fake, honest.Pub, clock, rng)
        clock.advance()
        m2, honest_sk, accepted_as = P.respond(honest, m1, net.directory, clock, rng)
        # Attacker lacks victim.Pr, so it unmasks X_j publicly (attack 1) instead.
        _, X_j = unmask_sender(m2.ADC, m2.IDbar, net.directory, pp)
        attacker_sk = P.session_key(st.X, X_j, victim.ID, honest.ID, st.T, m2.T)
    res.elapsed_s = t.elapsed
    res.recovered = {
        "Pr_TA": hex(pr_ta),
        "MK_TA": hex(mk_ta),
        "honest drone accepted peer as": accepted_as.hex(),
        "session key held by attacker": attacker_sk.hex(),
    }
    res.expected = {
        "Pr_TA": hex(net.ta.Pr_TA),
        "MK_TA": hex(net.ta.MK_TA),
        "honest drone accepted peer as": victim.ID.hex(),
        "session key held by attacker": honest_sk.hex(),
    }
    res.notes.append(f"attacker self-check Pr_TA.G == Pub_TA and MK_TA.G == MP_TA: {consistent}")
    res.notes.append("impersonated drone was never captured; honest drone completed the handshake")
    return res


def run_all(seed: int = 0) -> list[AttackResult]:
    return [
        demo_session_key_recovery(seed + 1),
        demo_forward_secrecy(seed + 2),
        demo_master_key_extraction(seed + 3),
    ]


if __name__ == "__main__":
    for r in run_all():
        print(r.report(), end="\n\n")
