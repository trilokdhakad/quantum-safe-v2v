"""Run the V2V network simulation and write metrics to CSV.

    python -m qsv2v.sim                                   # default sweep, 10-200 vehicles
    python -m qsv2v.sim --vehicles 10 50 --handshake pq-mldsa classical --seeds 0 1
    python -m qsv2v.sim --crypto real --vehicles 10       # real PQ-V2V-AKE inside the sim
    python -m qsv2v.sim --remeasure                       # re-time the crypto on this machine

Outputs (in --out, default results/sim):
    summary.csv     one row per run (configuration + every metric)
    handshakes.csv  one row per handshake
    bsm_pdr.csv     safety-message delivery by distance bin, per run
    crypto_profile.json  measured sizes and timings the runs used
"""

from __future__ import annotations

import argparse
import csv
import itertools
from pathlib import Path

from qsv2v.sim.network import SimConfig, run
from qsv2v.sim.profiles import load_or_measure, measure_all, save


def write_rows(path: Path, rows: list[dict], append: bool) -> None:
    if not rows:
        return
    exists = path.exists() and append
    with path.open("a" if exists else "w", newline="", encoding="utf-8") as f:
        fields = list(dict.fromkeys(k for r in rows for k in r))
        w = csv.DictWriter(f, fieldnames=fields)
        if not exists:
            w.writeheader()
        w.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--vehicles", type=int, nargs="+", default=[10, 25, 50, 100, 150, 200])
    ap.add_argument("--handshake", nargs="+", default=["classical", "pq-falcon", "pq-mldsa"],
                    help="handshake profiles, or 'none'")  # fmt: skip
    ap.add_argument("--bsm", nargs="+", default=["falcon"])
    ap.add_argument("--policy", nargs="+", default=["all"], choices=["all", "same_direction"])
    ap.add_argument("--slowdown", type=float, nargs="+", default=[1.0])
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--duration", type=float, default=4.0)
    ap.add_argument("--warmup", type=float, default=1.0)
    ap.add_argument("--crypto", choices=["model", "real"], default="model")
    ap.add_argument("--out", type=Path, default=Path("results/sim"))
    ap.add_argument("--append", action="store_true", help="append to existing CSVs")
    ap.add_argument("--remeasure", action="store_true")
    args = ap.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    prof_path = args.out / "crypto_profile.json"
    if args.remeasure:
        save(measure_all(), prof_path)
    profile = load_or_measure(prof_path)

    summaries, hs_rows, bin_rows = [], [], []
    grid = itertools.product(
        args.vehicles, args.handshake, args.bsm, args.policy, args.slowdown, args.seeds
    )
    for n, hp, bp, pol, slow, seed in grid:
        cfg = SimConfig(
            n_vehicles=n, duration=args.duration, warmup=args.warmup, seed=seed,
            bsm_profile=bp, handshake_profile=None if hp == "none" else hp,
            hs_policy=pol, cpu_slowdown=slow, crypto_mode=args.crypto,
        )  # fmt: skip
        res = run(cfg, profile)
        run_id = f"n{n}-{hp}-{bp}-{pol}-x{slow:g}-s{seed}"
        s = {"run_id": run_id, **res.summary}
        summaries.append(s)
        hs_rows += [{"run_id": run_id, **h} for h in res.handshakes]
        bin_rows += [{"run_id": run_id, **b} for b in res.bsm_bins]
        print(
            f"{run_id:42s} hs={s['hs_attempted']:4d} ok={s['hs_success_rate']!s:6s} "
            f"p50={s['hs_latency_ms_p50']!s:8s}ms p95={s['hs_latency_ms_p95']!s:8s}ms "
            f"cbr={s['cbr_mean']!s:6s} bsm_pdr={s['bsm_pdr_in_range']!s:6s} "
            f"({s['wall_seconds']} s)"
        )
    write_rows(args.out / "summary.csv", summaries, args.append)
    write_rows(args.out / "handshakes.csv", hs_rows, args.append)
    write_rows(args.out / "bsm_pdr.csv", bin_rows, args.append)
    print(f"wrote {len(summaries)} runs to {args.out}/summary.csv, handshakes.csv, bsm_pdr.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
