"""Attacks on PSLAP (Shariq et al., Computer Networks 2025).

1. Session linking. PID_AV = h(ID_AV || a_1) is fixed at registration.
   * Text variant (Section 4.3 / 6.3): msg1 carries PID_AV in clear, so any
     eavesdropper links every session of a vehicle, across drones and time.
   * Figure variant (Fig. 3): msg1 carries TID = h(X) xor PID. A passive
     outsider cannot unmask it (X needs Pr_D), and the demo checks that the
     same grouping fails. But every drone recovers the static PID in every
     session, so drones -- which the paper's own adversary model treats as
     untrusted -- link all sessions of a vehicle; colluding drones link
     globally.
2. Offline password guessing. The OBU stores beta = h(PWD) xor a_1,
   gamma = alpha xor h(a_1), delta = h(PID || PWD || alpha || beta). Identities
   are public in the paper's adversary model (Section 3.2), and the model lets
   the adversary expose OBU contents. Then each guess PWD* yields
   a_1* = beta xor h(PWD*), alpha* = gamma xor h(a_1*), PID* = h(ID || a_1*),
   and delta itself confirms the guess -- no online interaction.
"""

from __future__ import annotations

from collections import defaultdict

from qsv2v.attacks.common import AttackResult, SimClock, Timer
from qsv2v.attacks.pslap import protocol as P
from qsv2v.crypto import DeterministicRNG, h, xor_bytes

PAPER = "PSLAP (Computer Networks 2025)"


def make_fleet(seed: int, n_vehicles: int, n_drones: int, passwords: list[bytes]):
    rng = DeterministicRNG(seed)
    clock = SimClock()
    ta = P.setup(rng)
    drones = [P.register_drone(rng) for _ in range(n_drones)]
    vehicles = []
    for _ in range(n_vehicles):
        vehicles.append(P.register_vehicle(ta, rng, rng.choice(passwords), clock))
        clock.advance(3600)
    return rng, clock, ta, drones, vehicles


def record_traffic(rng, clock, ta, drones, vehicles, sessions_per_vehicle, variant):
    log = []
    for _ in range(sessions_per_vehicle):
        for av in vehicles:
            drone = rng.choice(drones)
            log.append(P.handshake(av, drone, ta, clock, rng, variant))
            clock.advance(30)
    # Shuffle so order carries no information.
    order = sorted(range(len(log)), key=lambda i: rng.bytes(8))
    return [log[i] for i in order]


def partition_by(keys) -> set[frozenset[int]]:
    groups = defaultdict(set)
    for i, k in enumerate(keys):
        groups[k].add(i)
    return {frozenset(g) for g in groups.values()}


# --------------------------------------------------------------------------
# Attack 1: session linking
# --------------------------------------------------------------------------
def link_passive(log: list[P.Session]) -> set[frozenset[int]]:
    """Eavesdropper: group sessions by the identity field of msg1."""
    return partition_by(s.msg1.ident for s in log)


def link_by_drones(log: list[P.Session], drones: dict[bytes, P.Drone]) -> set[frozenset[int]]:
    """Colluding drones: each unmasks the static PID of the sessions it served."""
    pids = []
    for s in log:
        d = drones[s.msg2.ID_D]
        Xp = d.Pr * s.msg1.Y
        pids.append(xor_bytes(h(P.point_bytes(Xp)), s.msg1.ident))
    return partition_by(pids)


def _score(found: set[frozenset[int]], truth: set[frozenset[int]]) -> str:
    return "exact partition" if found == truth else f"{len(found)} groups"


def demo_session_linking(
    seed: int = 4, n_vehicles: int = 6, n_drones: int = 4, sessions_per_vehicle: int = 5
) -> AttackResult:
    pw = [b"pw%04d" % i for i in range(100)]
    rng, clock, ta, drones, vehicles = make_fleet(seed, n_vehicles, n_drones, pw)
    res = AttackResult(
        PAPER,
        "Session linking via the static pseudo-identity PID_AV",
        "Prop. 2 (anonymity and untraceability)",
        "text variant: passive eavesdropper; figure variant: the drones themselves",
    )
    with Timer() as t:
        log_text = record_traffic(rng, clock, ta, drones, vehicles, sessions_per_vehicle, "text")
        truth_text = partition_by(s.vehicle_id for s in log_text)
        found_text = link_passive(log_text)

        log_fig = record_traffic(rng, clock, ta, drones, vehicles, sessions_per_vehicle, "figure")
        truth_fig = partition_by(s.vehicle_id for s in log_fig)
        passive_fig = link_passive(log_fig)
        found_fig = link_by_drones(log_fig, {d.ID: d for d in drones})
    res.elapsed_s = t.elapsed
    n = len(log_text)
    res.recovered = {
        "text variant, eavesdropper": _score(found_text, truth_text),
        "figure variant, colluding drones": _score(found_fig, truth_fig),
    }
    res.expected = {
        "text variant, eavesdropper": "exact partition",
        "figure variant, colluding drones": "exact partition",
    }
    res.notes.append(
        f"{n} sessions from {n_vehicles} vehicles over {n_drones} drones, shuffled; "
        f"truth = {len(truth_text)} groups of {sessions_per_vehicle}"
    )
    res.notes.append(
        "figure variant, passive eavesdropper grouping by TID: "
        f"{_score(passive_fig, truth_fig)} (no linking -- TID is masked per session)"
    )
    return res


# --------------------------------------------------------------------------
# Attack 2: offline password guessing from OBU contents
# --------------------------------------------------------------------------
def guess_password(id_av: bytes, obu: P.OBU, dictionary: list[bytes]):
    """Return (password, a1, alpha, PID, guesses tried) or None."""
    for n, pw in enumerate(dictionary, 1):
        a1 = xor_bytes(obu.beta, h(pw))
        alpha = xor_bytes(obu.gamma, h(a1))
        pid = h(id_av, a1)
        if h(pid, pw, alpha, obu.beta) == obu.delta:
            return pw, a1, alpha, pid, n
    return None


def synthetic_dictionary(size: int, rng: DeterministicRNG) -> list[bytes]:
    """Human-style passwords: word + digits. Stand-in for a real leaked list."""
    words = [
        b"falcon", b"tesla", b"drive", b"rover", b"summer", b"dragon", b"monkey", b"shadow",
        b"master", b"sunshine", b"princess", b"football", b"charlie", b"freedom", b"silver",
        b"orange", b"pepper", b"ginger", b"hunter", b"thunder", b"mustang", b"cooper",
        b"ranger", b"tiger", b"maverick", b"voyager", b"pilot", b"engine", b"turbo", b"nissan",
    ]  # fmt: skip
    out = {w + str(i).encode() for w in words for i in range(size // len(words) + 1)}
    out = sorted(out)[:size]
    return sorted(out, key=lambda _: rng.bytes(8))


def demo_password_guessing(seed: int = 5, dict_size: int = 20_000) -> AttackResult:
    rng = DeterministicRNG(seed)
    dictionary = synthetic_dictionary(dict_size, rng)
    clock = SimClock()
    ta = P.setup(rng)
    victim = P.register_vehicle(ta, rng, rng.choice(dictionary), clock)

    res = AttackResult(
        PAPER,
        "Offline password guessing from OBU contents",
        "Prop. 8 (AV capture: <beta, gamma, delta> are non-invertible)",
        "reads the OBU <beta, gamma, delta>; knows the public ID_AV (Section 3.2)",
    )
    with Timer() as t:
        hit = guess_password(victim.ID, victim.obu, dictionary)
    res.elapsed_s = t.elapsed
    if hit:
        pw, a1, alpha, pid, tries = hit
        res.recovered = {
            "password": pw.decode(),
            "a_1": a1.hex(),
            "alpha": alpha.hex(),
            "PID_AV": pid.hex(),
        }
        res.notes.append(f"{tries} guesses of a {dict_size}-word dictionary, offline")
    res.expected = {
        "password": victim.PWD.decode(),
        "a_1": victim.a1.hex(),
        "alpha": victim.alpha.hex(),
        "PID_AV": victim.PID.hex(),
    }
    res.notes.append(
        "success requires the password to be in the dictionary -- the standard "
        "offline-guessing model; delta gives a perfect test for each guess"
    )
    return res


def run_all(seed: int = 0) -> list[AttackResult]:
    return [demo_session_linking(seed + 4), demo_password_guessing(seed + 5)]


if __name__ == "__main__":
    for r in run_all():
        print(r.report(), end="\n\n")
