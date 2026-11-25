"""E1 -- Eavesdropper detection: QBER and abort rate vs Eve's intercept fraction.

Full BB84 runs (quantum phase, sifting, 10% QBER sample, abort above 11%, then
Cascade and privacy amplification) with an intercept-resend Eve attacking a
fraction f of the photons, on a clean channel and on one with 2% intrinsic noise.
Theory: Q = e + f/4 - f*e/2, so a clean channel aborts once f > 44%.
"""

from __future__ import annotations

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
    wilson,
    write_csv,
    write_outcome,
    write_table,
)
from qsv2v.qkd import InterceptResendEve, PauliNoise, QuantumChannel, expected_qber
from qsv2v.qkd.postprocess import run_qkd
from qsv2v.qkd.theory import QBER_THRESHOLD

NAME = "e01_eve_detection"
NOISES = [0.0, 0.02]


def abort_fraction_theory(e: float) -> float:
    """Eve fraction at which the expected QBER reaches the abort threshold."""
    return (QBER_THRESHOLD - e) / (0.25 - e / 2)


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    d = outdir(base, NAME)
    fs = np.round(np.arange(0, 1.0001, 0.25 if quick else 0.05), 2)
    seeds = range(3 if quick else 10)
    n = 10_000 if quick else 50_000
    rows = []
    for e in NOISES:
        noise = PauliNoise.from_qber(e) if e else None
        for f in fs:
            ch = QuantumChannel(noise=noise, eve=InterceptResendEve(float(f)) if f else None)
            for s in seeds:
                r = run_qkd(n, channel=ch, seed=SEED + s)
                rows.append({
                    "noise": e, "eve_fraction": float(f), "seed": s, "photons": n,
                    "qber_estimated": r.estimate.qber, "qber_sifted": r.bb84.qber,
                    "qber_theory": expected_qber(noise, float(f)),
                    "aborted": int(r.abort_reason == "qber_above_threshold"),
                    "final_key_bits": r.final_length,
                    "photons_intercepted": r.bb84.eve.n_intercepted if r.bb84.eve else 0,
                })  # fmt: skip
        log(f"  E1: noise {e:.0%} done")
    write_csv(d / "data.csv", rows)
    summ = aggregate(rows, ["noise", "eve_fraction"],
                     ["qber_estimated", "qber_theory", "final_key_bits"])  # fmt: skip
    for r in summ:
        k = sum(x["aborted"] for x in rows if x["noise"] == r["noise"]
                and x["eve_fraction"] == r["eve_fraction"])  # fmt: skip
        r["abort_rate"], r["abort_lo"], r["abort_hi"] = wilson(k, r["n"])
    write_csv(d / "summary.csv", summ)
    write_table(d / "table.md", summ, [
        ("noise", "Noise"), ("eve_fraction", "Eve fraction"), ("qber_estimated±", "QBER (est.)"),
        ("qber_theory", "QBER (theory)"), ("abort_rate", "Abort rate"),
        ("final_key_bits±", "Final key (bits)"), ("n", "Runs"),
    ])  # fmt: skip

    fig, (a1, a2) = figure(9.6, 3.6, ncols=2)
    xx = np.linspace(0, 1, 101)
    for i, e in enumerate(NOISES):
        pts = [r for r in summ if r["noise"] == e]
        x = [100 * r["eve_fraction"] for r in pts]
        lab = f"{e:.0%} channel noise"
        errline(
            a1,
            x,
            [100 * r["qber_estimated"] for r in pts],
            [100 * r["qber_estimated_ci95"] for r in pts],
            COLORS[i],
            lab + " (measured)",
        )
        noise = PauliNoise.from_qber(e) if e else None
        a1.plot(100 * xx, [100 * expected_qber(noise, f) for f in xx], color=COLORS[i], ls=":",
                lw=1.2, label=lab + " (theory)")  # fmt: skip
        rate = [100 * r["abort_rate"] for r in pts]
        err = [
            [max(0.0, v - 100 * r["abort_lo"]) for v, r in zip(rate, pts, strict=True)],
            [max(0.0, 100 * r["abort_hi"] - v) for v, r in zip(rate, pts, strict=True)],
        ]
        a2.errorbar(x, rate, yerr=err, marker="o", color=COLORS[i], label=lab, capsize=2,
                    elinewidth=0.8)  # fmt: skip
        a2.axvline(100 * abort_fraction_theory(e), color=COLORS[i], ls=":", lw=1)
    a1.axhline(100 * QBER_THRESHOLD, color="#555", ls="--", lw=1)
    a1.text(1, 100 * QBER_THRESHOLD + 0.4, "11% abort threshold", color="#555", fontsize=8)
    a1.set_title("QBER rises linearly with interception")
    a1.set_xlabel("Photons intercepted by Eve (%)")
    a1.set_ylabel("QBER (%)")
    a1.legend(fontsize=7.5, loc="upper left")
    a2.set_title("Alice and Bob abort when QBER > 11% (95% CI)")
    a2.set_xlabel("Photons intercepted by Eve (%)")
    a2.set_ylabel("Runs aborted (%)")
    a2.set_ylim(-2, 102)
    a2.legend(fontsize=8, loc="lower right")
    save(fig, d)

    clean = [r for r in summ if r["noise"] == 0.0]
    q100 = next(r["qber_estimated"] for r in clean if r["eve_fraction"] == 1.0)
    # Interpolated fraction where the abort rate crosses 50% on the clean channel.
    xs = [r["eve_fraction"] for r in clean]
    ys = [r["abort_rate"] for r in clean]
    f50 = float(np.interp(0.5, ys, xs)) if ys[-1] >= 0.5 and ys[0] < 0.5 else None
    ok = abs(q100 - 0.25) < 0.01 and f50 is not None and abs(f50 - 0.44) < 0.06
    return write_outcome(d, Outcome(
        "E1", "Eavesdropper detection",
        "QBER rises ~linearly to ~25%; abort beyond ~44% interception",
        f"Clean channel: QBER {q100:.1%} at full interception; half the runs abort at "
        f"f ≈ {f50:.0%} (theory 44%). With 2% noise the abort point falls to "
        f"{abort_fraction_theory(0.02):.0%}. Measured QBER matches Q = e + f/4 - fe/2.",
        ok, numbers={"qber_full_interception": q100, "abort_50pct_fraction": f50},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
