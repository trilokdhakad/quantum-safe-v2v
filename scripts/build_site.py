"""Copy the measured datasets into docs/data/ for the public project page (GitHub Pages).

    python -m qsv2v.experiments                 # experiment results
    python scripts/build_showcase_data.py       # datasets from the code and the experiments
    python scripts/build_site.py                # -> docs/data/*.json

The page (docs/index.html) draws every chart and table from these files; nothing
on it is typed in by hand except explanatory text. Each file keeps a short note
of where its numbers came from (the full generating code is in this repository).
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "results" / "showcase"
DEST = ROOT / "docs" / "data"
NAMES = [
    "phases", "tests", "qber_grid", "key_rate", "e3_distance", "attacks", "paper_errors",
    "defenses", "scyther", "bsm_sizes", "e7_cost", "crypto_ops", "sim_steady",
    "sim_broadcast", "experiments", "trace_classical", "trace_pq_mldsa",
]  # fmt: skip
ROUND = 5  # significant digits kept for floats (smaller files, no visible change)


def _round(x):
    if isinstance(x, float):
        return float(f"{x:.{ROUND}g}")
    if isinstance(x, list):
        return [_round(v) for v in x]
    if isinstance(x, dict):
        return {k: _round(v) for k, v in x.items()}
    return x


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    for name in NAMES:
        obj = json.loads((SRC / f"{name}.json").read_text(encoding="utf-8"))
        if isinstance(obj, dict) and "rows" in obj:
            source = next((m["value"] for m in obj.get("meta", []) if m["label"] == "Input"), "")
            obj = {"source": source, "rows": obj["rows"]}
        out = DEST / f"{name}.json"
        out.write_text(json.dumps(_round(obj), separators=(",", ":"), ensure_ascii=False),
                       encoding="utf-8")  # fmt: skip
        print(f"  {out.relative_to(ROOT)}: {out.stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
