"""E5 -- Attack success: every Phase 4 attack against the papers, and against PQ-V2V-AKE.

Each of the eight attacks on the base papers is run with several seeds (fresh
keys, identities and sessions each time); success means every recovered value
equals the victim's. The same attack classes are then run against PQ-V2V-AKE
(``qsv2v.pqc.attack_suite``), where success means the defence held and the
positive control (the attack's precondition really was met) passed.
"""

from __future__ import annotations

import inspect
import time
from pathlib import Path

from qsv2v.experiments.common import (
    COLORS,
    Outcome,
    figure,
    mean_ci,
    outdir,
    save,
    wilson,
    write_csv,
    write_outcome,
    write_table,
)

NAME = "e05_attack_success"


def paper_attacks(seed: int):
    from qsv2v.attacks import shor_demo
    from qsv2v.attacks.p2as_ioav import attacks as p2as
    from qsv2v.attacks.pslap import attacks as pslap
    from qsv2v.attacks.psrs_d2d import attacks as psrs

    return (psrs.run_all(seed) + pslap.run_all(seed) + p2as.run_all(seed)
            + [shor_demo.demo_shor(15, 15 + seed)])  # fmt: skip


def defences(seed: int):
    from qsv2v.pqc import attack_suite as S

    fns = [S.passive_key_recovery, S.forward_secrecy, S.capture_and_forge, S.forged_msg1,
           S.mitm_swap, S.linking, S.password_guessing, S.quantum_breaks_x25519]  # fmt: skip
    out = []
    for fn in fns:
        p = inspect.signature(fn).parameters.get("seed")
        t0 = time.perf_counter()
        r = fn(p.default + 100 * seed) if p else fn()
        out.append((r, time.perf_counter() - t0))
    return out


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    d = outdir(base, NAME)
    seeds = range(1 if quick else 5)
    rows = []
    for s in seeds:
        for r in paper_attacks(100 * s):
            rows.append({"target": "base paper", "paper": r.paper.split(" (")[0],
                         "attack": r.attack, "seed": s, "attacker": r.adversary,
                         "success": int(r.success), "seconds": r.elapsed_s})  # fmt: skip
        for r, secs in defences(s):
            rows.append({"target": "PQ-V2V-AKE", "paper": "PQ-V2V-AKE (ours)",
                         "attack": r.attack, "seed": s, "attacker": r.attacker,
                         "success": int(not r.blocked), "seconds": secs,
                         "analogue_of": r.analogue_of, "control": r.control})  # fmt: skip
        log(f"  E5: seed {s} done")
    write_csv(d / "data.csv", rows)
    summ = []
    keys = list(dict.fromkeys((r["target"], r["paper"], r["attack"]) for r in rows))
    for tgt, paper, attack in keys:
        rs = [r for r in rows if (r["target"], r["paper"], r["attack"]) == (tgt, paper, attack)]
        k = sum(r["success"] for r in rs)
        p, lo, hi = wilson(k, len(rs))
        mu, ci, _ = mean_ci(r["seconds"] for r in rs)
        summ.append({"target": tgt, "paper": paper, "attack": attack,
                     "analogue_of": rs[0].get("analogue_of", ""), "attacker": rs[0]["attacker"],
                     "successes": k, "runs": len(rs), "success_rate": p, "ci_low": lo,
                     "ci_high": hi, "seconds": mu, "seconds_ci95": ci})  # fmt: skip
    write_csv(d / "summary.csv", summ)
    write_table(d / "table.md", summ, [
        ("target", "Target"), ("paper", "Paper"), ("attack", "Attack"),
        ("analogue_of", "Analogue of"), ("successes", "Attack succeeded"), ("runs", "Runs"),
        ("seconds±", "Time per run (s)"),
    ], digits=3)  # fmt: skip

    paper_rows = [r for r in summ if r["target"] == "base paper"]
    import textwrap

    fig, ax = figure(8.6, 4.6)
    labels = [
        textwrap.fill(f"{r['paper']}: {r['attack']}", 46, max_lines=2, placeholder=" …")
        for r in paper_rows
    ][::-1]
    vals = [r["seconds"] for r in paper_rows][::-1]
    errs = [r["seconds_ci95"] if r["seconds_ci95"] == r["seconds_ci95"] else 0
            for r in paper_rows][::-1]  # fmt: skip
    ax.barh(labels, vals, xerr=errs, color=COLORS[0], height=0.55, error_kw={"lw": 1})
    for y, (v, r) in enumerate(zip(vals, paper_rows[::-1], strict=True)):
        e = errs[y]
        ax.text((v + e) * 1.2, y, f"{r['successes']}/{r['runs']} succeeded", va="center",
                fontsize=7.5)  # fmt: skip
    ax.set_xscale("log")
    ax.set_xlim(right=max(vals) * 30)
    ax.set_xlabel("Time to run the attack (s, log scale)")
    ax.set_title("Every attack on the base papers succeeds, in seconds")
    ax.tick_params(axis="y", labelsize=7.5)
    ax.grid(axis="y", visible=False)
    save(fig, d)

    paper_ok = all(r["successes"] == r["runs"] for r in paper_rows)
    ours = [r for r in summ if r["target"] == "PQ-V2V-AKE"]
    ours_ok = all(r["successes"] == 0 for r in ours)
    return write_outcome(d, Outcome(
        "E5", "Attack success",
        "Every listed attack succeeds on the paper, fails on PQ-V2V-AKE",
        f"{sum(r['successes'] for r in paper_rows)}/{sum(r['runs'] for r in paper_rows)} "
        f"attack runs on the base papers succeeded ({len(paper_rows)} attacks × "
        f"{len(seeds)} seeds, slowest {max(vals):.2f} s); "
        f"{sum(r['successes'] for r in ours)}/{sum(r['runs'] for r in ours)} succeeded "
        f"against PQ-V2V-AKE ({len(ours)} attack classes; where a test has a positive "
        "control, it is part of the pass condition).",
        paper_ok and ours_ok,
        numbers={"paper_success": sum(r["successes"] for r in paper_rows),
                 "paper_runs": sum(r["runs"] for r in paper_rows),
                 "ours_success": sum(r["successes"] for r in ours),
                 "ours_runs": sum(r["runs"] for r in ours)},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
