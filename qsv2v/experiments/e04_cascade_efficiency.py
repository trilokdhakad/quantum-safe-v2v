"""E4 -- Error-correction efficiency: Cascade leakage vs the Shannon limit.

Cascade (4 passes, block size doubling each pass) on random key pairs with a
binomial error pattern at each QBER, for four first-pass block sizes
k1 = ceil(c / Q), c in {0.5, 0.73, 1.0, 1.5}; c = 0.73 is the standard choice.
Efficiency f = leaked parity bits / (n h(Q)); f = 1 is the Shannon limit.
"""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np

from qsv2v.experiments.common import (
    COLORS,
    SEED,
    Outcome,
    aggregate,
    errline,
    figure,
    outdir,
    save,
    write_csv,
    write_outcome,
    write_table,
)
from qsv2v.qkd.cascade import cascade
from qsv2v.qkd.theory import binary_entropy

NAME = "e04_cascade_efficiency"
SCALES = [0.5, 0.73, 1.0, 1.5]


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    d = outdir(base, NAME)
    qs = [0.02, 0.05, 0.08] if quick else [0.005, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07,
                                           0.08, 0.09, 0.10]  # fmt: skip
    seeds = range(2 if quick else 8)
    n = 10_000 if quick else 50_000
    rows = []
    for c in SCALES:
        for q in qs:
            for s in seeds:
                rng = np.random.default_rng([SEED, s, int(1000 * q), int(100 * c)])
                alice = rng.integers(0, 2, n, dtype=np.uint8)
                bob = alice ^ (rng.random(n) < q).astype(np.uint8)
                q_true = float(np.mean(alice != bob))
                k1 = max(1, math.ceil(c / q))
                r = cascade(alice, bob, q, rng, k1=k1)
                resid = int(np.count_nonzero(r.corrected != alice))
                rows.append({
                    "block_scale": c, "qber": q, "seed": s, "n": n, "k1": k1,
                    "qber_true": q_true, "leaked_bits": r.leaked_bits,
                    "shannon_bits": n * float(binary_entropy(q_true)),
                    "efficiency_f": r.leaked_bits / (n * float(binary_entropy(q_true))),
                    "residual_errors": resid, "corrected_fully": int(resid == 0),
                })  # fmt: skip
        log(f"  E4: block scale {c} done")
    write_csv(d / "data.csv", rows)
    summ = aggregate(
        rows,
        ["block_scale", "qber"],
        ["efficiency_f", "leaked_bits", "residual_errors", "corrected_fully", "k1"],
    )
    write_csv(d / "summary.csv", summ)
    write_table(d / "table.md", summ, [
        ("block_scale", "c (k1 = c/Q)"), ("qber", "QBER"), ("k1", "k1"),
        ("efficiency_f±", "Efficiency f"), ("residual_errors±", "Residual errors"),
        ("corrected_fully", "Fully corrected (share)"), ("n", "Runs"),
    ])  # fmt: skip

    fig, a1 = figure(6.4, 3.8)
    for i, c in enumerate(SCALES):
        pts = [r for r in summ if r["block_scale"] == c]
        lab = f"k1 = {c}/Q" + (" (standard)" if c == 0.73 else "")
        errline(a1, [100 * r["qber"] for r in pts], [r["efficiency_f"] for r in pts],
                [r["efficiency_f_ci95"] for r in pts], COLORS[i], lab)  # fmt: skip
    a1.axhline(1.0, color="#555", ls="--", lw=1)
    a1.text(0.3, 1.01, "Shannon limit", color="#555", fontsize=8)
    a1.set_title("Cascade leakage relative to the Shannon limit")
    a1.set_xlabel("QBER (%)")
    a1.set_ylabel("Efficiency f = leaked / n·h(Q)")
    a1.legend(fontsize=8)
    save(fig, d)

    std = [r for r in summ if r["block_scale"] == 0.73 and r["qber"] >= 0.02]
    f_lo, f_hi = min(r["efficiency_f"] for r in std), max(r["efficiency_f"] for r in std)
    resid_std = sum(r["residual_errors"] for r in rows if r["block_scale"] == 0.73)
    resid_all = {c: sum(r["residual_errors"] for r in rows if r["block_scale"] == c)
                 for c in SCALES}  # fmt: skip
    f_mean = {c: sum(r["efficiency_f"] for r in summ if r["block_scale"] == c)
              / sum(1 for r in summ if r["block_scale"] == c) for c in SCALES}  # fmt: skip
    best = min(SCALES, key=lambda c: f_mean[c])
    ok = 1.05 <= f_lo and f_hi <= 1.3
    return write_outcome(d, Outcome(
        "E4", "Error-correction efficiency",
        "Cascade leaks ~1.1–1.2× the Shannon limit",
        f"With the standard k1 = 0.73/Q, Cascade leaks {f_lo:.2f}–{f_hi:.2f}× the Shannon "
        f"limit for QBER 2–10% ({resid_std} residual errors over all its runs). Mean f by "
        "first block: " + ", ".join(f"{c}/Q {f_mean[c]:.3f}" for c in SCALES)
        + "; residual errors: " + ", ".join(f"{c}/Q {resid_all[c]}" for c in SCALES)
        + f". Lowest leakage at k1 = {best}/Q in these runs.",
        ok, numbers={"f_min": f_lo, "f_max": f_hi, "residual_errors_standard": resid_std,
                 "f_mean_by_scale": f_mean, "residual_errors_by_scale": resid_all},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
