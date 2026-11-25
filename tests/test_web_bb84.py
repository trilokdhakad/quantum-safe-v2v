"""Phase 8: the in-browser BB84 (docs/assets/bb84.js) agrees with the Python simulator's theory.

Runs the page's JavaScript under Node; skipped when Node is not installed.
"""

import json
import math
import shutil
import subprocess
from pathlib import Path

import pytest

from qsv2v.qkd import PauliNoise, expected_qber

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "docs" / "assets" / "bb84.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js not installed")


def run_js(code: str):
    script = f"const B = require({json.dumps(str(JS))});\n{code}"
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


SETTINGS = [(0.0, 0.0), (0.0, 0.05), (0.3, 0.0), (0.5, 0.02), (1.0, 0.0), (1.0, 0.08)]


def test_qber_matches_python_theory():
    res = run_js(
        "const s = " + json.dumps(SETTINGS) + ";"
        " console.log(JSON.stringify(s.map(([f, e], k) => {"
        " const a = B.analyse(B.send(200000, f, e, 1000 + k), 1000 + k);"
        " return [f, e, a.qTrue, a.sifted, a.n]; })));"
    )
    for f, e, q, sifted, n in res:
        th = expected_qber(PauliNoise.from_qber(e) if e else None, f)
        assert th == pytest.approx(e + f / 4 - f * e / 2)  # same formula the page states
        sigma = math.sqrt(max(th * (1 - th), 1e-12) / sifted)
        assert abs(q - th) < 4 * sigma + 1e-9, (f, e, q, th)
        assert sifted / n == pytest.approx(0.5, abs=0.01)  # half the photons survive sifting


def test_no_noise_no_eve_keys_identical_and_seeded():
    res = run_js(
        "const p = B.send(5000, 0, 0, 7), q = B.send(5000, 0, 0, 7);"
        "console.log(JSON.stringify([p.filter(x => x.error).length,"
        " JSON.stringify(p) === JSON.stringify(q), B.analyse(p, 7).abort]));"
    )
    errors, same, abort = res
    assert errors == 0 and same and abort is False


def test_abort_rule_detects_eve():
    res = run_js(
        "console.log(JSON.stringify([0, 0.3, 0.6, 1].map((f) =>"
        " B.analyse(B.send(100000, f, 0, 3), 3).abort)));"
    )
    # Expected QBER 0, 7.5%, 15%, 25% against the 11% threshold.
    assert res == [False, False, True, True]


def test_key_estimate_falls_to_zero_near_ten_percent():
    res = run_js(
        "console.log(JSON.stringify([0.02, 0.05, 0.09, 0.105].map((e) =>"
        " B.analyse(B.send(200000, 0, e, 5), 5).keyBits)));"
    )
    assert res[0] > res[1] > res[2] > 0  # shrinking key as noise grows
    assert res[3] == 0  # (1 + 1.16) h(Q) > 1 just above 10%, as E2 measures
