"""Record the two simulation runs that the project page replays as an animation.

    python scripts/record_traces.py      # -> results/sim/traces/trace_{classical,pq-mldsa}.json

Same 60 vehicles, same seed, same Falcon-512 safety messages; only the handshake
differs. Each run lasts 12 s and only the last 6 s are kept, so the replay shows
steady-state traffic, not the start-up burst in which every vehicle meets all its
neighbours at once (the same warm-up rule as experiment E9). Times in the file
start at 0 at the beginning of the kept window.
"""

from __future__ import annotations

import json
from pathlib import Path

from qsv2v.sim.network import SimConfig, run
from qsv2v.sim.profiles import load_or_measure

ROOT = Path(__file__).resolve().parents[1]
N, SEED, DURATION, WARMUP, PERIOD = 60, 7, 12.0, 6.0, 0.05
KEEP = ["hs_attempted", "hs_success_rate", "hs_latency_ms_p50", "cbr_mean", "bsm_pdr_in_range"]


def trimmed(trace: dict, start: float) -> dict:
    k0 = round(start / trace["period"])
    events = []
    for e in trace["events"]:
        if e["t"] >= start:
            events.append({**e, "t": round(e["t"] - start, 4)})
    return {**trace, "x": trace["x"][k0:], "events": events, "window_start_s": start}


def main() -> None:
    profile = load_or_measure(ROOT / "results" / "sim" / "crypto_profile.json")
    out = ROOT / "results" / "sim" / "traces"
    out.mkdir(parents=True, exist_ok=True)
    for hp in ("classical", "pq-mldsa"):
        cfg = SimConfig(n_vehicles=N, duration=DURATION, warmup=WARMUP, seed=SEED,
                        handshake_profile=hp, bsm_profile="falcon", trace=True,
                        trace_period=PERIOD)  # fmt: skip
        res = run(cfg, profile)
        tr = trimmed(res.trace, WARMUP)
        tr["profile"] = hp
        tr["summary"] = {k: res.summary.get(k) for k in KEEP}  # steady-state window only
        path = out / f"trace_{hp}.json"
        path.write_text(json.dumps(tr, separators=(",", ":")), encoding="utf-8")
        s = tr["summary"]
        print(f"{path.name}: {len(tr['events'])} events, handshakes {s['hs_attempted']}, "
              f"success {s['hs_success_rate']}, median {s['hs_latency_ms_p50']} ms")  # fmt: skip


if __name__ == "__main__":
    main()
