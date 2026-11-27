"""The numbers the public page writes on its charts (docs/assets/figmath.js) match the theory.

The page annotates its figures with values it computes from docs/data/: where each noise level
crosses the 11% abort line, where the key fraction reaches zero, the fitted dB/km decay and the
"1 in N" wording of the log axis. Runs the page's JavaScript under Node; skipped without Node.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from qsv2v import formulas as F

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "docs" / "assets" / "figmath.js"
DATA = ROOT / "docs" / "data"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js not installed")


def rows(name: str) -> list[dict]:
    obj = json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))
    return obj["rows"] if isinstance(obj, dict) and "rows" in obj else obj


def js(expr: str, **args):
    """Evaluate `expr` with figmath.js loaded as M and each keyword argument bound as JSON."""
    binds = "".join(f"const {k} = {json.dumps(v)};\n" for k, v in args.items())
    head = f"const M = require({json.dumps(str(JS))});\n"
    script = f"{head}{binds}console.log(JSON.stringify({expr}));"
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_abort_crossings_match_the_closed_form():
    grid = rows("qber_grid")
    got = js("M.eveCrossings(g, 0.11).map((c) => [c.name, c.f])", g=grid)
    rate = {r["noise"]: r["noise_rate"] for r in grid}
    assert len(got) == 4
    for name, f in got:
        assert f == pytest.approx(F.abort_fraction(rate[name]), abs=1e-9), name
    assert round(100 * got[0][1]) == 44  # the "caught at 44%" label on a clean channel


def test_zero_points_on_the_key_rate_chart():
    kr = rows("key_rate")
    best, meas = js(
        "[M.zeroAt(d, 'qber', 'shor_preskill'), M.zeroAt(d, 'qber', 'key_fraction')]", d=kr
    )
    # The perfect-code curve ends at the Shor-Preskill limit; the label rounds it to 11%.
    assert best == pytest.approx(F.zero_key_qber(1.0), abs=2e-4)
    assert round(100 * best) == 11
    # The measured curve ends between its last positive grid point and its first zero.
    last_pos = max(r["qber"] for r in kr if r["key_fraction"] > 0)
    first_zero = min(r["qber"] for r in kr if r["qber"] > last_pos)
    assert last_pos <= meas <= first_zero
    assert round(100 * meas) == 10


def test_zero_at_is_exact_on_lines_and_stays_inside_the_bracket():
    def line(a, b, xs):
        return [{"x": x, "y": max(0.0, a - b * x)} for x in xs]

    xs = [0.0, 0.05, 0.1, 0.15, 0.2]
    assert js("M.zeroAt(d, 'x', 'y')", d=line(0.3, 3, xs)) == pytest.approx(0.1)
    assert js("M.zeroAt(d, 'x', 'y')", d=line(0.25, 3, xs)) == pytest.approx(0.25 / 3)
    # A curve that meets zero tangentially: the answer never leaves [last positive, first zero].
    curved = [{"x": x, "y": max(0.0, (0.11 - x)) ** 2} for x in [0.09, 0.1, 0.105, 0.11, 0.115]]
    z = js("M.zeroAt(d, 'x', 'y')", d=curved)
    assert 0.105 <= z <= 0.11
    assert js("M.zeroAt(d, 'x', 'y')", d=line(1.0, 0.0, xs)) is None  # never reaches zero


E3_RESULT = ROOT / "results" / "experiments" / "e03_distance_loss" / "result.json"


def test_db_per_km_fit_and_cutoff_match_the_theory():
    e3 = rows("e3_distance")
    link = F.LinkModel()
    slope = js("M.e3Slope(d)", d=e3)
    # The key rate decays with the fibre loss (report §1.7): 0.2 dB/km.
    assert slope == pytest.approx(link.alpha_db_per_km, abs=0.01)
    # "No key at 190 km": the first 10 km grid point past the predicted cut-off (182.1 km).
    first_zero = min(r["distance_km"] for r in e3 if r["skr_asymptotic"] <= 0)
    last_key = max(r["distance_km"] for r in e3 if r["skr_asymptotic"] > 0)
    assert last_key < link.cutoff_km() <= first_zero


@pytest.mark.skipif(not E3_RESULT.exists(), reason="run python -m qsv2v.experiments first")
def test_db_per_km_fit_matches_the_experiment():
    e3 = rows("e3_distance")
    result = json.loads(E3_RESULT.read_text(encoding="utf-8"))
    # Same least-squares fit as the experiment; the page's data keeps 5 significant digits.
    assert js("M.e3Slope(d)", d=e3) == pytest.approx(result["numbers"]["db_per_km"], abs=1e-3)
    first_zero = min(r["distance_km"] for r in e3 if r["skr_asymptotic"] <= 0)
    assert first_zero == result["numbers"]["cutoff_km"]


def test_log_axis_in_words():
    got = js("[1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7].map(M.inWords)")
    assert got == ["1 in 10", "1 in 100", "1 in 1k", "1 in 10k", "1 in 100k", "1 in 1M", "1 in 10M"]
