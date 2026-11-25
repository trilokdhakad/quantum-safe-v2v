"""Phase 7: experiment scripts, statistics helpers and the one-command runner."""

import json
import math

import numpy as np
import pytest

from qsv2v.experiments import __main__ as runner
from qsv2v.experiments import common as C
from qsv2v.experiments import (
    e02_channel_noise,
    e03_distance_loss,
    e04_cascade_efficiency,
    e07_handshake_cost,
    e08_message_size,
    e09_network_scale,
)


# -- statistics -------------------------------------------------------------------
def test_mean_ci_matches_t_interval():
    m, half, n = C.mean_ci([1.0, 2.0, 3.0, 4.0, float("nan")])
    assert (m, n) == (2.5, 4)
    # t_{0.975, 3} = 3.182; s = 1.291; half = 3.182 * 1.291 / 2
    assert half == pytest.approx(3.1824 * np.std([1, 2, 3, 4], ddof=1) / 2, rel=1e-3)
    assert math.isnan(C.mean_ci([5.0])[1])
    assert math.isnan(C.mean_ci([])[0])


def test_wilson_interval():
    p, lo, hi = C.wilson(0, 10)
    assert p == 0 and lo == 0 and 0.2 < hi < 0.35
    p, lo, hi = C.wilson(5, 10)
    assert lo < 0.5 < hi


def test_aggregate_groups_and_ci():
    rows = [{"g": "a", "x": 1}, {"g": "a", "x": 3}, {"g": "b", "x": 10}]
    out = {r["g"]: r for r in C.aggregate(rows, ["g"], ["x"])}
    assert out["a"]["x"] == 2 and out["a"]["n"] == 2 and out["b"]["x"] == 10
    assert out["a"]["x_ci95"] > 0


def test_write_table_shows_ci(tmp_path):
    C.write_table(tmp_path / "t.md", [{"k": 1.5, "k_ci95": 0.25}], [("k±", "K")])
    assert "1.5 ± 0.25" in (tmp_path / "t.md").read_text("utf-8")


# -- experiments (quick settings) -------------------------------------------------------
def _files(d):
    return {p.name for p in d.iterdir()}


def test_e02_quick_outputs(tmp_path):
    o = e02_channel_noise.run(tmp_path, quick=True, log=lambda *_: None)
    d = tmp_path / e02_channel_noise.NAME
    assert {"data.csv", "summary.csv", "table.md", "figure.png", "figure.pdf",
            "result.json"} <= _files(d)  # fmt: skip
    assert o.numbers["wrong_keys"] == 0
    assert json.loads((d / "result.json").read_text("utf-8"))["key"] == "E2"


def test_e02_zero_crossing():
    assert e02_channel_noise.zero_crossing([0, 1, 2], [1.0, 0.5, -0.5]) == pytest.approx(1.5)
    assert e02_channel_noise.zero_crossing([0, 1], [1.0, 0.5]) is None


def test_e03_quick_follows_fibre_loss(tmp_path):
    o = e03_distance_loss.run(tmp_path, quick=True, log=lambda *_: None)
    assert o.supported  # 0.2 dB/km decay recovered from the simulated detections
    assert o.numbers["db_per_km"] == pytest.approx(0.2, rel=0.15)


def test_e04_quick_efficiency_band(tmp_path):
    o = e04_cascade_efficiency.run(tmp_path, quick=True, log=lambda *_: None)
    assert 1.0 < o.numbers["f_min"] <= o.numbers["f_max"] < 1.35


def test_e07_wire_size_and_scalar_mult_count():
    from qsv2v.attacks.psrs_d2d.protocol import Msg1
    from qsv2v.crypto.ec import G

    m = Msg1(IDbar=b"x" * 32, Y=G, ADC=5, U=b"u" * 32, T=1)
    assert e07_handshake_cost.wire_size(m) == 32 + 64 + 32 + 32 + 4
    with e07_handshake_cost.count_scalar_mults() as box:
        _ = 3 * G
        _ = G * 5
    assert box["n"] == 2


def test_e08_sizes(tmp_path):
    o = e08_message_size.run(tmp_path, quick=True, log=lambda *_: None)
    assert o.supported
    assert o.numbers["ECDSA P-256 (today, IEEE 1609.2)"]["digest"] <= 1400


def test_e09_plan_and_budget_rule():
    jobs = e09_network_scale.plan(quick=True)
    assert {j["sweep"] for j in jobs} == {"handshake", "broadcast", "speed"}
    ids = {e09_network_scale.job_id(j, "p") for j in jobs}
    assert len(ids) == len(jobs)  # every run cached under its own key
    summ = [{"sweep": "handshake", "handshake_profile": "x", "hs_policy": "all",
             "n_vehicles": n, "hs_latency_ms_p50": lat}
            for n, lat in [(10, 20), (25, 60), (50, 140), (100, 90)]]  # fmt: skip
    # Stops at the first density over budget, even if a later one dips back under.
    assert e09_network_scale.max_n_under_budget(summ, "handshake_profile", "x", "all") == 25
    # A point with no handshakes (NaN) is skipped, not treated as over budget.
    summ[0]["hs_latency_ms_p50"] = float("nan")
    assert e09_network_scale.max_n_under_budget(summ, "handshake_profile", "x", "all") == 25
    # The conservative rule uses mean + CI.
    summ[1]["hs_latency_ms_p50_ci95"] = 50
    assert e09_network_scale.max_n_under_budget(summ, "handshake_profile", "x", "all", True) is None


def test_runner_only_and_summary(tmp_path, monkeypatch):
    calls = []

    def fake_run(base, quick, log=print):
        calls.append(quick)
        d = C.outdir(base, "e08_message_size")
        fig, ax = C.figure()
        ax.plot([0, 1], [0, 1])
        C.save(fig, d)
        return C.write_outcome(d, C.Outcome("E8", "t", "h", "f", True))

    monkeypatch.setattr(e08_message_size, "run", fake_run)
    assert runner.main(["--only", "e08", "--quick", "--out", str(tmp_path)]) == 0
    assert calls == [True]
    assert (tmp_path / "figures" / "E08.png").exists()
    s = (tmp_path / "SUMMARY.md").read_text("utf-8")
    assert "| E8 | t | h | Supported | f |" in s
