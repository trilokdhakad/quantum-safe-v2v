"""E3 -- Distance / loss: detection rate and secret key rate vs link distance.

Fibre-like loss (0.2 dB/km), detector efficiency 20%, dark-count probability
1e-5 per pulse and 1% intrinsic error, with an ideal single-photon source. The
number of pulses grows with distance so every point has enough detections.

Two key rates are reported per point:

* end-to-end: final key bits / pulses sent, from the full pipeline (includes the
  fixed 131-bit verification and security overhead, so it drops out early);
* asymptotic: (detections / 2) * (1 - (1 + f) h(Q)) from the measured detection
  rate and QBER, the rate a long run would reach.
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
from qsv2v.qkd import PauliNoise, QuantumChannel
from qsv2v.qkd.postprocess import run_qkd
from qsv2v.qkd.theory import binary_entropy, detection_probability, expected_qber

NAME = "e03_distance_loss"
ALPHA, DET_EFF, DARK, NOISE = 0.2, 0.2, 1e-5, 0.01
F_EC = 1.16  # Cascade efficiency measured in E2 (used when a run has no Cascade data)


def theory(dist):
    """Asymptotic secret key rate per pulse and QBER for the channel above."""
    eta = DET_EFF * 10 ** (-ALPHA * dist / 10)
    p = detection_probability(eta, DARK)
    q = expected_qber(PauliNoise.from_qber(NOISE), 0.0, eta, DARK)
    return max(0.0, p / 2 * (1 - (1 + F_EC) * float(binary_entropy(q)))), q, p


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    d = outdir(base, NAME)
    dists = [0, 50, 100, 150] if quick else list(range(0, 201, 10))
    seeds = range(2 if quick else 5)
    cap = 1_000_000 if quick else 10_000_000
    rows = []
    for dist in dists:
        ch = QuantumChannel(noise=PauliNoise.from_qber(NOISE), distance_km=dist,
                            attenuation_db_per_km=ALPHA, detector_efficiency=DET_EFF,
                            dark_count_prob=DARK)  # fmt: skip
        p_det = detection_probability(ch.eta, DARK)
        n = int(min(cap, max(200_000, 50_000 / p_det)))
        for s in seeds:
            r = run_qkd(n, channel=ch, seed=SEED + s)
            q = r.true_qber
            f = r.ec_efficiency if not math.isnan(r.ec_efficiency) else F_EC
            det = r.bb84.detection_rate
            rows.append({
                "distance_km": dist, "seed": s, "pulses": n, "eta": ch.eta,
                "detection_rate": det, "qber": q, "aborted": int(r.aborted),
                "final_key_bits": r.final_length, "skr_end_to_end": r.secret_key_rate,
                "skr_asymptotic": max(0.0, det / 2 * (1 - (1 + f) * float(binary_entropy(q)))),
            })  # fmt: skip
        log(f"  E3: {dist} km done ({n:,} pulses)")
    write_csv(d / "data.csv", rows)
    summ = aggregate(rows, ["distance_km"], ["detection_rate", "qber", "final_key_bits",
                                             "skr_end_to_end", "skr_asymptotic"])  # fmt: skip
    for r in summ:
        r["skr_theory"], r["qber_theory"], r["detection_theory"] = theory(r["distance_km"])
    write_csv(d / "summary.csv", summ)
    write_table(d / "table.md", summ, [
        ("distance_km", "km"), ("detection_rate±", "Detection rate"), ("qber±", "QBER"),
        ("skr_asymptotic±", "Key rate (asymptotic, bits/pulse)"),
        ("skr_end_to_end±", "Key rate (end-to-end)"), ("skr_theory", "Key rate (theory)"),
        ("final_key_bits±", "Final key (bits)"), ("n", "Seeds"),
    ], digits=3)  # fmt: skip

    fig, (a1, a2) = figure(9.6, 3.7, ncols=2)
    dd = np.linspace(0, max(dists), 400)
    th = [theory(x) for x in dd]
    x = [r["distance_km"] for r in summ]
    a1.plot(dd, [t[2] for t in th], color=COLORS[4], ls=":", lw=1.2, label="Theory")
    a1.plot(x, [r["detection_rate"] for r in summ], "o", color=COLORS[0], label="Measured")
    a1.set_yscale("log")
    a1.set_title("Bob's detection rate falls exponentially")
    a1.set_xlabel("Link distance (km, 0.2 dB/km)")
    a1.set_ylabel("Detections per pulse (log)")
    a1.legend(fontsize=8)
    pos = [r for r in summ if r["skr_asymptotic"] > 0]
    a2.plot(dd, [max(t[0], 1e-12) for t in th], color=COLORS[4], ls=":", lw=1.2,
            label=f"Theory (f = {F_EC})")  # fmt: skip
    errline(a2, [r["distance_km"] for r in pos], [r["skr_asymptotic"] for r in pos],
            [r["skr_asymptotic_ci95"] for r in pos], COLORS[0],
            "From measured detections and QBER")  # fmt: skip
    e2e = [r for r in summ if r["skr_end_to_end"] > 0]
    a2.plot([r["distance_km"] for r in e2e], [r["skr_end_to_end"] for r in e2e], "s",
            color=COLORS[1], ms=4, label="End-to-end final key")  # fmt: skip
    a2.set_yscale("log")
    a2.set_ylim(1e-7, 0.2)
    a2.set_title("Secret key rate vs distance")
    a2.set_xlabel("Link distance (km, 0.2 dB/km)")
    a2.set_ylabel("Secret key bits per pulse (log)")
    a2.legend(fontsize=8, loc="lower left")
    save(fig, d)

    # Exponential decay check: slope of log10(rate) vs distance over the loss-dominated range.
    fit = [r for r in summ if 0 < r["skr_asymptotic"] and r["distance_km"] <= 120]
    slope = float(np.polyfit([r["distance_km"] for r in fit],
                             np.log10([r["skr_asymptotic"] for r in fit]), 1)[0])  # fmt: skip
    cutoff = next((r["distance_km"] for r in summ if r["skr_asymptotic"] <= 0), None)
    ok = abs(slope * 10 / -ALPHA - 1) < 0.15  # ≈ -0.02 decades per km = -0.2 dB/km
    return write_outcome(d, Outcome(
        "E3", "Distance / loss",
        "Key rate decays exponentially with distance",
        f"Key rate falls {-10 * slope:.2f} dB per km up to 120 km (fibre loss is "
        f"{ALPHA} dB/km), then dark counts push QBER past the Cascade limit; first distance "
        f"with no key: {cutoff} km.",
        ok, numbers={"db_per_km": -10 * slope, "cutoff_km": cutoff},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
