"""E10 -- QKD vs PQC for V2V: security basis, key rate, hardware, practicality.

A comparison table built from this project's own measurements where they exist:

* QKD key rate from the E3 channel (measured detection rate and QBER, or the E3
  theory when E3 has not been run), at an assumed 100 MHz single-photon source;
* PQC key rate from the E7 compute time of one PQ-V2V-AKE handshake (one 256-bit
  key per handshake, one CPU core) and the E9 empty-channel handshake latency.

Assumptions the table states explicitly: the QKD numbers use the fibre-like loss
model of E3 (0.2 dB/km); a free-space link to a moving vehicle has larger and
time-varying loss, so they are an upper bound for V2V. The ideal single-photon
source is also optimistic (real systems use attenuated lasers with decoy states).
"""

from __future__ import annotations

import csv
from pathlib import Path

import numpy as np

from qsv2v.experiments.common import (
    COLORS,
    RESULTS,
    Outcome,
    figure,
    outdir,
    save,
    write_csv,
    write_outcome,
    write_table,
)
from qsv2v.experiments.e03_distance_loss import theory as qkd_theory

NAME = "e10_qkd_vs_pqc"
PULSE_RATE = 100e6  # pulses per second (assumption)
KEY_BITS = 256
RADIO_RANGE_KM = 0.3


def _csv(path: Path) -> list[dict] | None:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def pqc_handshake_ms(base: Path) -> tuple[float, str]:
    rows = _csv(base / "e07_handshake_cost" / "summary.csv")
    if rows:
        r = next(r for r in rows if r["protocol"] == "PQ-V2V-AKE"
                 and r["variant"] == "ML-KEM-768 + ML-DSA-44")  # fmt: skip
        return float(r["compute_ms"]), "E7 (measured)"
    import time

    from qsv2v.pqc import pq_v2v_ake as A
    from qsv2v.pqc.sig import oqs_available

    be = dict(kem_backend="oqs", sig_backend="oqs") if oqs_available() else {}
    net = A.setup_network(2, 0, **be)
    A.handshake(*net.vehicles, net.clock)
    ts = []
    for _ in range(10):
        t0 = time.perf_counter()
        A.handshake(*net.vehicles, net.clock)
        ts.append(time.perf_counter() - t0)
    return 1000 * float(np.median(ts)), "measured here (E7 not run)"


def pqc_latency_ms(base: Path) -> tuple[float | None, str]:
    rows = _csv(base / "e09_network_scale" / "summary.csv")
    if rows:
        r = [x for x in rows if x["sweep"] == "handshake" and x["handshake_profile"] == "pq-mldsa"
             and x["hs_policy"] == "all" and float(x["n_vehicles"]) == 10]  # fmt: skip
        if r:
            return float(r[0]["hs_latency_ms_p50"]), "E9, 10 vehicles"
    return None, "E9 not run"


def other_facts(base: Path) -> dict:
    """Numbers quoted from E7, E8 and E9, when those experiments have been run."""
    f = {"hs_bytes": "see E7", "bsm_bytes": "see E8", "speed": "see E9"}
    e7 = _csv(base / "e07_handshake_cost" / "summary.csv")
    if e7:
        r = next(r for r in e7 if r["variant"] == "ML-KEM-768 + ML-DSA-44")
        f["hs_bytes"] = f"{int(float(r['bytes_total'])):,} B per handshake (E7)"
    e8 = _csv(base / "e08_message_size" / "summary.csv")
    if e8:
        r = next(r for r in e8 if r["vehicle_alg"] == "ML-DSA-44")
        f["bsm_bytes"] = (
            f"ML-DSA-44 safety message {int(float(r['msg_with_digest_bytes'])):,} B (E8)"
        )
    e9 = _csv(base / "e09_network_scale" / "summary.csv")
    if e9:
        sp = [r for r in e9 if r["sweep"] == "speed" and r["handshake_profile"] == "pq-mldsa"]
        if sp:
            lo = min(float(r["hs_success_rate"]) for r in sp)
            hi = max(float(r["hs_success_rate"]) for r in sp)
            kmh = sorted(108 * float(r["speed_scale"]) for r in sp)
            f["speed"] = (
                f"Handshake success {lo:.0%}–{hi:.0%} for mean speeds "
                f"{kmh[0]:.0f}–{kmh[-1]:.0f} km/h (E9)"
            )
    return f


def qkd_rate(base: Path, dist_km: float) -> tuple[float, str]:
    """Secret bits per pulse at ``dist_km``: E3 measurement if that distance was run."""
    rows = _csv(base / "e03_distance_loss" / "summary.csv")
    if rows:
        for r in rows:
            if float(r["distance_km"]) == dist_km:
                return float(r["skr_asymptotic"]), "E3 (measured)"
    return qkd_theory(dist_km)[0], "E3 model"


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    root = base or RESULTS
    d = outdir(base, NAME)
    hs_ms, hs_src = pqc_handshake_ms(root)
    lat_ms, lat_src = pqc_latency_ms(root)
    pqc_bps = KEY_BITS * 1000 / hs_ms
    r0, src0 = qkd_rate(root, 0)
    r50, src50 = qkd_rate(root, 50)
    q0_bps, q50_bps = r0 * PULSE_RATE, r50 * PULSE_RATE
    # Time for QKD to collect one post-processing block of 10^5 sifted bits at 0 km.
    block = 100_000
    det0 = qkd_theory(0)[2]
    t_block = block / (det0 / 2 * PULSE_RATE)
    facts = other_facts(root)
    cutoff = next(x for x in range(0, 400) if qkd_theory(x)[0] <= 0)
    rows = [
        {"aspect": "Security basis", "qkd": "Physics: any measurement disturbs the states "
         "(E1: Eve raises QBER to 25% and is detected)", "pqc": "Hardness of module lattice "
         "problems (ML-KEM, ML-DSA); no known quantum attack", "source": "E1, Phase 5"},
        {"aspect": "Strength of guarantee", "qkd": "Information-theoretic, if devices "
         "match the model; side channels in real detectors have been exploited",
         "pqc": "Computational; standardised by NIST (FIPS 203/204, 2024)", "source": "—"},
        {"aspect": "Needs authentication anyway", "qkd": "Yes: the classical channel must be "
         "authenticated (e.g. with PQC signatures)", "pqc": "Built in (ML-DSA certificates)",
         "source": "—"},
        {"aspect": "Secret key rate", "qkd": f"{q0_bps:,.0f} bit/s at 0 km, {q50_bps:,.0f} bit/s "
         f"at 50 km (100 MHz source, ideal single photons; {src0})",
         "pqc": f"{pqc_bps:,.0f} bit/s per CPU core (one 256-bit key per {hs_ms:.1f} ms "
         f"handshake; {hs_src})", "source": "E3, E7"},
        {"aspect": "Time to first key", "qkd": f"{1000 * t_block:.1f} ms of photons at 0 km "
         f"to fill one 10^5-bit block, plus Cascade round trips",
         "pqc": (f"{lat_ms:.0f} ms over 802.11p on an empty road ({lat_src})" if lat_ms else
                 "see E9"), "source": "E3, E9"},
        {"aspect": "Range", "qkd": f"Loss-limited: no key beyond {cutoff} km of fibre in "
         "this model (dark counts); free-space to a moving car is much harder",
         "pqc": "Radio range "
         "(~300 m direct); any distance through infrastructure", "source": "E3"},
        {"aspect": "Hardware", "qkd": "Single-photon source and detectors, optical "
         "alignment, line of sight between vehicles", "pqc": "Software on the existing "
         "on-board unit", "source": "—"},
        {"aspect": "Mobility", "qkd": "Beam must track a vehicle moving at up to 70 m/s "
         "relative speed", "pqc": facts["speed"],
         "source": "E9"},
        {"aspect": "Cost on the radio channel", "qkd": "None for the quantum part; classical "
         "post-processing messages", "pqc": f"Large messages: {facts['bsm_bytes']}; "
         f"{facts['hs_bytes']}", "source": "E7, E8"},
        {"aspect": "Deployable now", "qkd": "No (lab and fixed-link systems only)",
         "pqc": "Yes", "source": "—"},
    ]  # fmt: skip
    write_csv(d / "data.csv", rows)
    write_csv(d / "summary.csv", rows)
    write_table(
        d / "table.md",
        rows,
        [
            ("aspect", "Aspect"),
            ("qkd", "QKD (BB84)"),
            ("pqc", "PQC (PQ-V2V-AKE)"),
            ("source", "From"),
        ],
    )
    log("  E10: done")

    fig, ax = figure(6.4, 3.8)
    dd = np.concatenate([[0.01], np.linspace(0.05, 200, 800)])
    qk = np.array([qkd_theory(x)[0] * PULSE_RATE for x in dd])
    ax.plot(dd[qk > 0], qk[qk > 0], color=COLORS[0], label="QKD, BB84 (E3 model, 100 MHz source)")
    meas = _csv(root / "e03_distance_loss" / "summary.csv")
    if meas:
        pts = [(float(r["distance_km"]), float(r["skr_asymptotic"]) * PULSE_RATE) for r in meas]
        pts = [(x, y) for x, y in pts if y > 0 and x > 0]
        ax.plot(*zip(*pts, strict=True), "o", color=COLORS[0], ms=4, label="QKD, measured (E3)")
    ax.plot([0.01, RADIO_RANGE_KM], [pqc_bps] * 2, color=COLORS[1], lw=2.4,
            label="PQ-V2V-AKE, direct radio range")  # fmt: skip
    ax.plot([RADIO_RANGE_KM, 200], [pqc_bps] * 2, color=COLORS[1], ls="--", lw=1.4,
            label="PQ-V2V-AKE, via infrastructure")  # fmt: skip
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Distance between the two parties (km, log)")
    ax.set_ylabel("Secret key throughput (bit/s, log)")
    ax.set_title("Key throughput vs distance (QKD curve: optimistic fibre model)")
    ax.legend(fontsize=7.5, loc="lower left")
    save(fig, d)

    return write_outcome(d, Outcome(
        "E10", "QKD vs PQC",
        "PQC is deployable now; QKD is strongest in theory but needs line-of-sight optics",
        f"PQC: {pqc_bps:,.0f} bit/s of key per core, software only. QKD: {q0_bps:,.0f} bit/s at "
        f"0 km and {q50_bps:,.0f} bit/s at 50 km in an optimistic fibre-like model, with "
        "dedicated optics and line of sight. QKD's guarantee is stronger in principle; PQC is "
        "the only option that works on today's vehicles.",
        None, numbers={"pqc_bps": pqc_bps, "qkd_bps_0km": q0_bps, "qkd_bps_50km": q50_bps,
                       "pqc_handshake_ms": hs_ms, "pqc_latency_ms": lat_ms},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
