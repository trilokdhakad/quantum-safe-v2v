"""Steady-state simulation sweep, run in parallel processes, merged into one CSV set.

    python scripts/run_steady_sweep.py [--jobs 12] [--duration 12] [--warmup 6]

Each (policy, vehicle count) pair runs as its own ``python -m qsv2v.sim`` process
(3 handshake profiles x seeds). A long warm-up excludes the start-up burst in
which every vehicle discovers all its neighbours at once; short runs include
that burst and overstate congestion. Output: results/sim/steady/{summary,
handshakes,bsm_pdr}.csv.
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_job(policy: str, n: int, args) -> Path:
    out = ROOT / "results" / "sim" / "steady" / f"{policy}_n{n}"
    out.mkdir(parents=True, exist_ok=True)
    prof = ROOT / "results" / "sim" / "crypto_profile.json"
    (out / "crypto_profile.json").write_bytes(prof.read_bytes())  # same measured costs everywhere
    cmd = [
        sys.executable, "-m", "qsv2v.sim", "--vehicles", str(n), "--policy", policy,
        "--handshake", "classical", "pq-falcon", "pq-mldsa", "--bsm", "falcon",
        "--seeds", *map(str, args.seeds), "--duration", str(args.duration),
        "--warmup", str(args.warmup), "--out", str(out),
    ]  # fmt: skip
    log = (out / "run.log").open("w", encoding="utf-8")
    subprocess.run(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    return out


def merge(dirs: list[Path], dest: Path) -> None:
    for name in ("summary.csv", "handshakes.csv", "bsm_pdr.csv"):
        rows = []
        for d in dirs:
            p = d / name
            if p.exists():
                rows += list(csv.DictReader(p.open(encoding="utf-8")))
        if not rows:
            continue
        fields = list(dict.fromkeys(k for r in rows for k in r))
        with (dest / name).open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        print(f"merged {len(rows)} rows into {dest / name}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--duration", type=float, default=12.0)
    ap.add_argument("--warmup", type=float, default=6.0)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1])
    ap.add_argument("--vehicles", type=int, nargs="+", default=[10, 25, 50, 100, 150, 200])
    ap.add_argument("--policies", nargs="+", default=["all", "same_direction"])
    args = ap.parse_args()
    jobs = [(p, n) for n in sorted(args.vehicles, reverse=True) for p in args.policies]
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        dirs = list(ex.map(lambda j: run_job(j[0], j[1], args), jobs))
    merge(dirs, ROOT / "results" / "sim" / "steady")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
