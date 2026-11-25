"""E9 -- Network scale: handshake latency, success and channel load for 10-200 vehicles.

Three sweeps of the Phase 6 simulator, all in steady state (the first seconds,
when every vehicle discovers all its neighbours at once, are discarded):

* handshakes: classical / PQ-Falcon / PQ-ML-DSA x every-neighbour / same-direction
  sessions x 10-200 vehicles (safety messages signed with Falcon-512);
* broadcast only: ECDSA / Falcon-512 / ML-DSA-44 safety messages, no handshakes;
* speed: lane speeds x0.5 / x1 / x1.5 at 50 vehicles.

Runs execute in parallel processes; each finished run is cached under ``runs/``
so an interrupted sweep resumes, and ``--fresh`` recomputes everything.
"""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path

from qsv2v.experiments.common import (
    COLORS,
    ROOT,
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

NAME = "e09_network_scale"
PROFILE_PATH = ROOT / "results" / "sim" / "crypto_profile.json"
HS = [("classical", "Classical (X25519 + ECDSA)"), ("pq-falcon", "PQ: ML-KEM + Falcon-512"),
      ("pq-mldsa", "PQ: ML-KEM + ML-DSA-44")]  # fmt: skip
BSM = [("ecdsa", "ECDSA P-256"), ("falcon", "Falcon-512"), ("mldsa", "ML-DSA-44")]
POLICIES = [("all", "Every neighbour"), ("same_direction", "Same direction only")]
METRICS = ["hs_success_rate", "hs_latency_ms_p50", "hs_latency_ms_p95", "hs_within_100ms",
           "cbr_mean", "bsm_pdr_in_range", "bsm_latency_ms_p95", "cpu_util_max",
           "hs_attempted", "hs_per_second"]  # fmt: skip


def plan(quick: bool) -> list[dict]:
    vehicles = [10, 25] if quick else [10, 25, 50, 100, 150, 200]
    seeds = [0] if quick else [0, 1, 2, 3, 4]
    dur, warm = (3.0, 1.0) if quick else (12.0, 6.0)
    base = dict(duration=dur, warmup=warm)
    jobs = []
    for n in vehicles:
        for hp, _ in HS:
            for pol, _ in POLICIES:
                for s in seeds:
                    jobs.append(
                        dict(
                            sweep="handshake",
                            n_vehicles=n,
                            handshake_profile=hp,
                            bsm_profile="falcon",
                            hs_policy=pol,
                            seed=s,
                            **base,
                        )
                    )
        for bp, _ in BSM:
            for s in seeds:
                jobs.append(dict(sweep="broadcast", n_vehicles=n, handshake_profile=None,
                                 bsm_profile=bp, hs_policy="all", seed=s, **base))  # fmt: skip
    for scale in [0.5, 1.0, 1.5] if not quick else [0.5, 1.5]:
        for hp, _ in HS:
            for s in seeds:
                jobs.append(dict(sweep="speed", n_vehicles=25 if quick else 50,
                                 handshake_profile=hp, bsm_profile="falcon", hs_policy="all",
                                 seed=s, speed_scale=scale, **base))  # fmt: skip
    return jobs


def job_id(job: dict, profile_hash: str) -> str:
    blob = json.dumps({**job, "profile": profile_hash}, sort_keys=True)
    return hashlib.sha1(blob.encode()).hexdigest()[:16]


def run_job(job: dict, profile_path: str) -> dict:
    """One simulation run (executed in a worker process)."""
    from qsv2v.sim.mobility import HighwayConfig
    from qsv2v.sim.network import SimConfig, run
    from qsv2v.sim.profiles import load

    hw = HighwayConfig()
    scale = job.get("speed_scale", 1.0)
    hw = replace(hw, lane_speeds=tuple(v * scale for v in hw.lane_speeds))
    cfg = SimConfig(
        n_vehicles=job["n_vehicles"], duration=job["duration"], warmup=job["warmup"],
        seed=job["seed"], bsm_profile=job["bsm_profile"],
        handshake_profile=job["handshake_profile"], hs_policy=job["hs_policy"], highway=hw,
    )  # fmt: skip
    res = run(cfg, load(Path(profile_path)))
    return {**job, "speed_scale": scale, **res.summary}


def sweep(d: Path, quick: bool, fresh: bool, workers: int | None, log=print) -> list[dict]:
    from qsv2v.sim.profiles import load_or_measure

    load_or_measure(PROFILE_PATH)  # measured once on this machine, shared by all runs
    prof_bytes = PROFILE_PATH.read_bytes()
    (d / "crypto_profile.json").write_bytes(prof_bytes)
    ph = hashlib.sha1(prof_bytes).hexdigest()[:12]
    cache = d / ("runs_quick" if quick else "runs")
    cache.mkdir(exist_ok=True)
    jobs = plan(quick)
    rows, todo = [], []
    for j in jobs:
        p = cache / f"{job_id(j, ph)}.json"
        if p.exists() and not fresh:
            rows.append(json.loads(p.read_text("utf-8")))
        else:
            todo.append((j, p))
    log(f"  E9: {len(rows)} cached runs, {len(todo)} to simulate")
    # Biggest runs first so the pool stays busy to the end.
    todo.sort(key=lambda jp: -jp[0]["n_vehicles"])
    workers = workers or max(1, (os.cpu_count() or 2) - 2)
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(run_job, j, str(PROFILE_PATH)): p for j, p in todo}
        for k, f in enumerate(as_completed(futs), 1):
            row = f.result()
            futs[f].write_text(json.dumps(row, default=float), "utf-8")
            rows.append(row)
            if k % 10 == 0 or k == len(todo):
                log(f"  E9: {k}/{len(todo)} runs done")
    return rows


def max_n_under_budget(
    summ: list[dict], key: str, value: str, pol: str, conservative: bool = False
) -> int | None:
    """Largest vehicle count with mean median latency <= 100 ms at it and every smaller count.

    Points with no handshake in the measured window (e.g. 10 vehicles, same direction:
    all sessions finish during warm-up) carry no information and are skipped.
    ``conservative`` uses the upper end of the 95% CI instead of the mean.
    """
    pts = sorted(
        (r["n_vehicles"], r["hs_latency_ms_p50"], r.get("hs_latency_ms_p50_ci95"))
        for r in summ
        if r["sweep"] == "handshake" and r[key] == value and r["hs_policy"] == pol
    )
    best = None
    for n, lat, ci in pts:
        if lat is None or lat != lat:
            continue
        if conservative and ci is not None and ci == ci:
            lat += ci
        if lat > 100:
            break
        best = n
    return best


def run(base: Path | None = None, quick: bool = False, fresh: bool = False,
        workers: int | None = None, log=print) -> Outcome:  # fmt: skip
    d = outdir(base, NAME)
    rows = sweep(d, quick, fresh, workers, log)
    for r in rows:
        r["handshake_profile"] = r["handshake_profile"] or "none"
    write_csv(d / "data.csv", sorted(rows, key=lambda r: (r["sweep"], r["n_vehicles"])))
    summ = aggregate(rows, ["sweep", "n_vehicles", "handshake_profile", "bsm_profile",
                            "hs_policy", "speed_scale"], METRICS)  # fmt: skip
    summ.sort(key=lambda r: (r["sweep"], r["hs_policy"], r["handshake_profile"],
                             r["bsm_profile"], r["speed_scale"], r["n_vehicles"]))  # fmt: skip
    write_csv(d / "summary.csv", summ)

    # Figure 1: handshake latency and success vs vehicles, both policies.
    fig, axes = figure(9.6, 6.4, ncols=2, nrows=2, sharex=True)
    for col, (pol, pol_name) in enumerate(POLICIES):
        for i, (hp, name) in enumerate(HS):
            pts = [r for r in summ if r["sweep"] == "handshake" and r["handshake_profile"] == hp
                   and r["hs_policy"] == pol]  # fmt: skip
            x = [r["n_vehicles"] for r in pts]
            errline(axes[0][col], x, [r["hs_latency_ms_p50"] for r in pts],
                    [r["hs_latency_ms_p50_ci95"] for r in pts], COLORS[i], name)  # fmt: skip
            errline(axes[1][col], x, [100 * r["hs_success_rate"] for r in pts],
                    [100 * r["hs_success_rate_ci95"] for r in pts], COLORS[i], name)  # fmt: skip
        axes[0][col].axhline(100, color="#555", ls="--", lw=1)
        axes[0][col].text(
            0.99,
            100,
            "100 ms budget ",
            color="#555",
            fontsize=8,
            ha="right",
            va="bottom",
            transform=axes[0][col].get_yaxis_transform(),
        )
        axes[0][col].set_yscale("log")
        axes[0][col].set_title(f"{pol_name}: median handshake latency")
        axes[0][col].set_ylabel("Median latency (ms, log scale)")
        axes[1][col].set_title(f"{pol_name}: handshakes that succeed")
        axes[1][col].set_ylabel("Success rate (%)")
        axes[1][col].set_ylim(0, 102)
        axes[1][col].set_xlabel("Vehicles on the 2 km, 6-lane highway")
    axes[1][0].legend(loc="lower left", fontsize=8)
    save(fig, d, "figure")

    # Figure 2: broadcast-only safety-message delivery and channel load.
    fig, axes = figure(9.6, 3.6, ncols=2)
    for i, (bp, name) in enumerate(BSM):
        pts = [r for r in summ if r["sweep"] == "broadcast" and r["bsm_profile"] == bp]
        x = [r["n_vehicles"] for r in pts]
        errline(axes[0], x, [100 * r["bsm_pdr_in_range"] for r in pts],
                [100 * r["bsm_pdr_in_range_ci95"] for r in pts], COLORS[i], name)  # fmt: skip
        errline(axes[1], x, [100 * r["cbr_mean"] for r in pts],
                [100 * r["cbr_mean_ci95"] for r in pts], COLORS[i], name)  # fmt: skip
    axes[0].set_title("Safety messages delivered and verified (≤ 300 m)")
    axes[0].set_ylabel("Delivery ratio (%)")
    axes[1].set_title("Channel busy ratio")
    axes[1].set_ylabel("Share of time the channel is busy (%)")
    for ax in axes:
        ax.set_ylim(0, 102)
        ax.set_xlabel("Vehicles on the 2 km, 6-lane highway")
    axes[0].legend(loc="lower left", fontsize=8)
    save(fig, d, "figure_broadcast")

    # Figure 3: speed sweep.
    fig, ax = figure(5.2, 3.4)
    for i, (hp, name) in enumerate(HS):
        pts = [r for r in summ if r["sweep"] == "speed" and r["handshake_profile"] == hp]
        errline(
            ax,
            [108 * r["speed_scale"] for r in pts],
            [100 * r["hs_success_rate"] for r in pts],
            [100 * r["hs_success_rate_ci95"] for r in pts],
            COLORS[i],
            name,
        )
    n_speed = next((r["n_vehicles"] for r in summ if r["sweep"] == "speed"), 50)
    ax.set_title(f"Handshake success vs traffic speed ({n_speed} vehicles)")
    ax.set_xlabel("Mean speed of the middle lane (km/h)")
    ax.set_ylabel("Success rate (%)")
    ax.set_ylim(0, 102)
    ax.legend(fontsize=8, loc="lower left")
    save(fig, d, "figure_speed")

    write_table(d / "table.md", [r for r in summ if r["sweep"] != "speed"], [
        ("sweep", "Sweep"), ("hs_policy", "Policy"), ("handshake_profile", "Handshake"),
        ("bsm_profile", "Safety-msg sig."), ("n_vehicles", "Vehicles"),
        ("hs_success_rate±", "HS success"), ("hs_latency_ms_p50±", "HS p50 (ms)"),
        ("hs_latency_ms_p95±", "HS p95 (ms)"), ("cbr_mean±", "Channel busy"),
        ("bsm_pdr_in_range±", "BSM delivery"), ("n", "Seeds"),
    ], digits=3)  # fmt: skip

    limits = {f"{hp}/{pol}": max_n_under_budget(summ, "handshake_profile", hp, pol)
              for hp, _ in HS for pol, _ in POLICIES}  # fmt: skip
    cons = {f"{hp}/{pol}": max_n_under_budget(summ, "handshake_profile", hp, pol, True)
            for hp, _ in HS for pol, _ in POLICIES}  # fmt: skip
    pdr200 = {bp: next((r["bsm_pdr_in_range"] for r in summ if r["sweep"] == "broadcast"
                        and r["bsm_profile"] == bp and r["n_vehicles"] == max(
                            x["n_vehicles"] for x in summ)), None) for bp, _ in BSM}  # fmt: skip
    a = limits
    ordered = all(
        (a[f"classical/{p}"] or 0) >= (a[f"pq-falcon/{p}"] or 0) >= (a[f"pq-mldsa/{p}"] or 0)
        for p, _ in POLICIES
    )
    finding = (
        "Largest density with median handshake latency ≤ 100 ms (every neighbour / same "
        f"direction): classical {a['classical/all']} / {a['classical/same_direction']}, "
        f"PQ-Falcon {a['pq-falcon/all']} / {a['pq-falcon/same_direction']}, PQ-ML-DSA "
        f"{a['pq-mldsa/all']} / {a['pq-mldsa/same_direction']} vehicles (upper 95% CI ≤ "
        f"100 ms: {cons['classical/all']} / {cons['classical/same_direction']}, "
        f"{cons['pq-falcon/all']} / {cons['pq-falcon/same_direction']}, "
        f"{cons['pq-mldsa/all']} / {cons['pq-mldsa/same_direction']}). Safety messages "
        f"only, at the highest density: delivery {pdr200['ecdsa']:.0%} (ECDSA), "
        f"{pdr200['falcon']:.0%} (Falcon-512), {pdr200['mldsa']:.0%} (ML-DSA-44)."
    )
    return write_outcome(d, Outcome(
        "E9", "Network scale",
        "Latency stays under the 100 ms budget up to a measurable density, lower for PQ",
        finding, supported=ordered and a["pq-mldsa/all"] is not None,
        numbers={"max_vehicles_under_100ms": limits, "max_vehicles_upper_ci_under_100ms": cons,
                 "bsm_pdr_at_max_density": pdr200,
                 "runs": len(rows)},
    ))  # fmt: skip


if __name__ == "__main__":
    o = run()
    print(o.finding)
