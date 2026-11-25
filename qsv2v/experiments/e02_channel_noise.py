"""E2 -- Channel noise: QBER and final key length as noise rises from 0 to 15%.

Full BB84 + Cascade + Toeplitz privacy amplification (asymptotic mode) at each
noise level. The final key reaches zero where (1 + f) h(Q) = 1, with f the
measured Cascade efficiency; a perfect code (f = 1) gives the Shor-Preskill 11%.
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
    write_csv,
    write_outcome,
    write_table,
)
from qsv2v.qkd import PauliNoise, QuantumChannel
from qsv2v.qkd.postprocess import PostProcessingConfig, run_qkd
from qsv2v.qkd.theory import asymptotic_key_fraction, binary_entropy

NAME = "e02_channel_noise"


def zero_crossing(x, y) -> float | None:
    """First x where y falls to zero (linear interpolation)."""
    for k in range(1, len(x)):
        if y[k - 1] > 0 >= y[k]:
            return float(x[k - 1] + (x[k] - x[k - 1]) * y[k - 1] / (y[k - 1] - y[k]))
    return None


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    d = outdir(base, NAME)
    qs = np.round(np.arange(0, 0.1501, 0.03 if quick else 0.005), 3)
    seeds = range(3 if quick else 10)
    n = 20_000 if quick else 100_000
    # Abort threshold lifted so the key-length collapse above 11% is measured, not skipped.
    cfg = PostProcessingConfig(qber_threshold=0.5)
    rows = []
    for q in qs:
        ch = QuantumChannel(noise=PauliNoise.from_qber(float(q)) if q else None)
        for s in seeds:
            r = run_qkd(n, channel=ch, seed=SEED + s, config=cfg)
            rows.append({
                "noise": float(q), "seed": s, "photons": n, "qber_measured": r.true_qber,
                "sifted_bits": r.n_key, "leaked_ec_bits": r.leaked_ec,
                "cascade_f": r.ec_efficiency, "final_key_bits": r.final_length,
                "key_fraction": r.key_fraction, "keys_identical": int(r.keys_match),
                "wrong_key": int(not r.aborted and r.final_length > 0 and not r.keys_match),
            })  # fmt: skip
    log("  E2: done")
    write_csv(d / "data.csv", rows)
    summ = aggregate(rows, ["noise"], ["qber_measured", "final_key_bits", "key_fraction",
                                       "cascade_f", "keys_identical", "wrong_key"])  # fmt: skip
    write_csv(d / "summary.csv", summ)
    write_table(d / "table.md", summ, [
        ("noise", "Noise"), ("qber_measured±", "QBER"), ("cascade_f±", "Cascade f"),
        ("final_key_bits±", "Final key (bits)"), ("key_fraction±", "Key fraction"),
        ("keys_identical", "Identical keys (share)"), ("wrong_key", "Wrong keys (share)"),
    ])  # fmt: skip

    x = np.array([r["qber_measured"] for r in summ])
    y = np.array([r["key_fraction"] for r in summ])
    f_mean = float(np.nanmean([r["cascade_f"] for r in summ if r["noise"] > 0.01]))
    fig, ax = figure(6.0, 3.8)
    qq = np.linspace(0.0005, 0.15, 300)
    ax.plot(100 * qq, asymptotic_key_fraction(qq), color=COLORS[4], ls="--", lw=1.2,
            label="Shor–Preskill bound (perfect code)")  # fmt: skip
    ax.plot(100 * qq, np.maximum(0, 1 - (1 + f_mean) * binary_entropy(qq)), color=COLORS[1],
            ls=":", lw=1.4, label=f"Predicted with Cascade f = {f_mean:.2f}")  # fmt: skip
    errline(ax, 100 * x, y, [r["key_fraction_ci95"] for r in summ], COLORS[0],
            f"Measured ({n:,} photons, {len(seeds)} seeds)")  # fmt: skip
    ax.set_title("Final key per sifted bit vs channel QBER")
    ax.set_xlabel("Measured QBER (%)")
    ax.set_ylabel("Final key bits per sifted bit")
    ax.set_ylim(-0.02, 1.02)
    ax.legend(fontsize=8)
    save(fig, d)

    q0 = zero_crossing(x, y)
    wrong = sum(r["wrong_key"] for r in rows)
    ok = q0 is not None and 0.09 <= q0 <= 0.105 and wrong == 0
    return write_outcome(d, Outcome(
        "E2", "Channel noise",
        "Key length falls to zero near 9.7% QBER with Cascade (11% with a perfect code)",
        f"Final key reaches zero at QBER ≈ {q0:.1%} (mean Cascade f = {f_mean:.2f}); "
        f"{wrong} of {len(rows)} runs ended with mismatched keys.",
        ok, numbers={"zero_key_qber": q0, "cascade_f": f_mean, "wrong_keys": wrong},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
