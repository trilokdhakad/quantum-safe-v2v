"""Shared helpers for the experiment scripts: output folders, statistics, figures, tables.

Every experiment writes into ``results/experiments/eNN_name/``:

* ``data.csv``       -- every measured row (one per seed / setting)
* ``summary.csv``    -- aggregated rows (mean and 95% confidence interval)
* ``table.md``       -- the same summary as a Markdown table (for the report)
* ``figure.png/pdf`` -- the figure (where the experiment has one)
* ``result.json``    -- headline numbers and the hypothesis verdict
"""

from __future__ import annotations

import csv
import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "results" / "experiments"
SEED = 20261125

# Colour order for series (validated categorical palette, fixed order).
COLORS = ["#2a78d6", "#e3741c", "#1f9e6e", "#b0399d", "#6b6f7a", "#c9a227"]


@dataclass
class Outcome:
    """What an experiment found, in a form the summary page can print."""

    key: str
    title: str
    hypothesis: str
    finding: str
    supported: bool | str | None  # True / False / "partly"; None = not a yes/no hypothesis
    numbers: dict = field(default_factory=dict)
    files: list[str] = field(default_factory=list)


# -- statistics ----------------------------------------------------------------
def mean_ci(values: Iterable[float], conf: float = 0.95) -> tuple[float, float, int]:
    """Mean and half-width of the t-based confidence interval (NaNs dropped)."""
    from scipy import stats

    v = np.asarray([x for x in values if x is not None and not math.isnan(x)], dtype=float)
    n = v.size
    if n == 0:
        return float("nan"), float("nan"), 0
    m = float(v.mean())
    if n == 1:
        return m, float("nan"), 1
    half = float(stats.t.ppf(0.5 + conf / 2, n - 1) * v.std(ddof=1) / math.sqrt(n))
    return m, half, n


def wilson(k: int, n: int, conf: float = 0.95) -> tuple[float, float, float]:
    """Proportion with a Wilson score interval: (p, low, high)."""
    from scipy import stats

    if n == 0:
        return float("nan"), float("nan"), float("nan")
    z = float(stats.norm.ppf(0.5 + conf / 2))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def aggregate(rows: list[dict], by: Sequence[str], metrics: Sequence[str]) -> list[dict]:
    """Group rows by ``by`` and report mean, 95% CI half-width and n for each metric."""
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r.get(k) for k in by), []).append(r)
    out = []
    for key, rs in groups.items():
        row = dict(zip(by, key, strict=True))
        for m in metrics:
            mu, half, n = mean_ci(_num(r.get(m)) for r in rs)
            row[m] = mu
            row[m + "_ci95"] = half
        row["n"] = len(rs)
        out.append(row)
    return out


def _num(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return float("nan")


# -- output ----------------------------------------------------------------------
def outdir(base: Path | None, name: str) -> Path:
    d = (base or RESULTS) / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fmt(x, digits: int = 4) -> str:
    if x is None:
        return "—"
    if isinstance(x, float):
        if math.isnan(x):
            return "—"
        return f"{x:.{digits}g}"
    return str(x)


def write_table(path: Path, rows: list[dict], cols: Sequence[tuple[str, str]], digits=4) -> None:
    """Markdown table; ``cols`` is a list of (key, header). A key 'x±' shows x with its CI."""
    lines = ["| " + " | ".join(h for _, h in cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        cells = []
        for k, _ in cols:
            if k.endswith("±"):
                k = k[:-1]
                ci = r.get(k + "_ci95")
                cell = fmt(r.get(k), digits)
                if ci is not None and not (isinstance(ci, float) and math.isnan(ci)):
                    cell += " ± " + fmt(ci, 2)
                cells.append(cell)
            else:
                cells.append(fmt(r.get(k), digits))
        lines.append("| " + " | ".join(cells) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_outcome(d: Path, o: Outcome) -> Outcome:
    o.files = sorted(p.name for p in d.iterdir() if p.is_file())
    (d / "result.json").write_text(json.dumps(o.__dict__, indent=1, default=float), "utf-8")
    return o


# -- figures --------------------------------------------------------------------------
def figure(width: float = 6.4, height: float = 4.0, ncols: int = 1, nrows: int = 1, **kw):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.size": 9.5,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.color": "#e3e3e3",
            "grid.linewidth": 0.6,
            "axes.edgecolor": "#888888",
            "axes.titlesize": 10,
            "axes.titleweight": "bold",
            "legend.frameon": False,
            "lines.linewidth": 1.8,
            "lines.markersize": 4.5,
            "savefig.dpi": 200,
        }
    )
    return plt.subplots(nrows, ncols, figsize=(width, height), **kw)


def errline(ax, x, y, ci, color, label, marker="o", **kw):
    """Line with markers and a shaded 95% CI band."""
    x, y, ci = (np.asarray(a, dtype=float) for a in (x, y, ci))
    ax.plot(x, y, marker=marker, color=color, label=label, **kw)
    ok = ~np.isnan(ci)
    if ok.any():
        ax.fill_between(x[ok], (y - ci)[ok], (y + ci)[ok], color=color, alpha=0.18, lw=0)


def save(fig, d: Path, name: str = "figure") -> None:
    fig.tight_layout()
    fig.savefig(d / f"{name}.png", bbox_inches="tight")
    fig.savefig(d / f"{name}.pdf", bbox_inches="tight")
    import matplotlib.pyplot as plt

    plt.close(fig)
