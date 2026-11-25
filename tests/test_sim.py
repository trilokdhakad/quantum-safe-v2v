"""Phase 6: highway mobility, radio channel, and the V2V network simulation."""

import csv

import numpy as np
import pytest
import simpy
from conftest import OQS

from qsv2v.sim import __main__ as cli
from qsv2v.sim.mobility import Highway, HighwayConfig
from qsv2v.sim.network import SimConfig, Simulation, run
from qsv2v.sim.profiles import BroadcastProfile, CryptoProfile, HandshakeProfile
from qsv2v.sim.radio import Medium, RadioConfig

# A fixed synthetic profile so tests do not depend on this machine's timings.
PROFILE = CryptoProfile(
    "test",
    {
        "pq-mldsa": HandshakeProfile("pq-mldsa", 7490, 7430, 38, 5e-4, 7e-4, 3e-4, 1e-5).__dict__,
        "classical": HandshakeProfile("classical", 379, 415, 38, 1e-4, 4e-4, 3e-4, 1e-5).__dict__,
    },
    {
        "falcon": BroadcastProfile(
            "falcon", "Falcon-512", "Falcon-512", 900, 2538, 3e-4, 5e-5, 5e-5
        ).__dict__,
        "mldsa": BroadcastProfile(
            "mldsa", "ML-DSA-44", "ML-DSA-44", 2665, 6481, 4e-4, 1e-4, 1e-4
        ).__dict__,
    },
)


def placed(xs, ys, length=10_000.0):
    """A static highway with vehicles at chosen (x, y) positions."""
    hw = Highway(len(xs), HighwayConfig(length=length), np.random.default_rng(0))
    hw.x0 = np.asarray(xs, float)
    hw.y = np.asarray(ys, float)
    hw.v = np.zeros(len(xs))
    return hw


# -- mobility -------------------------------------------------------------------
def test_ring_wraparound_distance():
    hw = placed([10.0, 1990.0], [0.0, 0.0], length=2000.0)
    assert hw.distance(0, 1, 0.0) == pytest.approx(20.0)


def test_motion_and_directions():
    cfg = HighwayConfig()
    hw = Highway(100, cfg, np.random.default_rng(1))
    assert set(hw.direction) == {1, -1}
    assert (hw.speed > 0).all()
    assert np.all((hw.x(123.4) >= 0) & (hw.x(123.4) < cfg.length))
    # Opposite directions are on opposite sides of the median.
    assert (np.sign(hw.y) == hw.direction).all()
    assert hw.density_per_km_lane() == pytest.approx(100 / 2 / 6)


def test_highway_validation():
    with pytest.raises(ValueError):
        Highway(0, HighwayConfig(), np.random.default_rng(0))
    with pytest.raises(ValueError):
        Highway(5, HighwayConfig(lanes=2), np.random.default_rng(0))


# -- radio -----------------------------------------------------------------------
def test_airtime_and_fragments():
    r = RadioConfig()
    assert r.airtime(1400) == pytest.approx(40e-6 + 1444 * 8 / 6e6)
    assert r.fragments(900) == [900]
    assert r.fragments(7490) == [1400] * 5 + [490]
    assert sum(r.fragments(6481)) == 6481


def test_decode_probability_and_edca():
    r = RadioConfig()
    p = r.decode_prob(np.array([0.0, 150.0, 300.0, 450.0]))
    assert p[0] > 0.99 and p[2] == pytest.approx(0.5) and p[3] < 0.01
    assert np.all(np.diff(p) < 0)
    vo, be = r.access_params(False), r.access_params(True)
    assert vo[0] < be[0] and vo[1] < be[1]  # safety messages win the channel


def _medium(hw, seed=0):
    env = simpy.Environment()
    return env, Medium(env, hw, RadioConfig(), np.random.default_rng(seed))


def test_broadcast_reaches_neighbours_only():
    env, m = _medium(placed([0, 100, 1000], [0, 0, 0]))
    out = {}

    def p():
        out["rx"], out["att"] = yield from m.send_frame(0, 500)

    env.process(p())
    env.run()
    assert list(out["rx"]) == [1] and out["att"] == 1


def test_hidden_terminal_collision():
    """A and C cannot hear each other (900 m) but both reach B: simultaneous frames collide at B."""
    env, m = _medium(placed([0, 450, 900], [0, 0, 0]))
    m.cfg = RadioConfig(comm_range=500, cs_range=450, interference_range=600)
    got = {}

    def send(i):
        got[i], _ = yield from m.send_frame(i, 1400)

    env.process(send(0))
    env.process(send(2))
    env.run()
    assert 1 not in got[0] and 1 not in got[2]


def test_carrier_sense_avoids_collision():
    """Two senders that hear each other take turns, so a nearby receiver gets both frames."""
    env, m = _medium(placed([0, 50, 100], [0, 0, 0]))
    got = {}

    def send(i):
        got[i], _ = yield from m.send_frame(i, 1400)

    env.process(send(0))
    env.process(send(2))
    env.run()
    assert 1 in got[0] and 1 in got[2]
    assert m.stats.defers >= 1


def test_unicast_out_of_range_exhausts_retries():
    env, m = _medium(placed([0, 2000], [0, 0]))
    out = {}

    def p():
        out["rx"], out["att"] = yield from m.send_frame(0, 300, dest=1)

    env.process(p())
    env.run()
    assert out["rx"] == [] and out["att"] == RadioConfig().retry_limit + 1
    assert m.stats.unicast_drops == 1


# -- network ------------------------------------------------------------------------
def test_deterministic_with_seed():
    a = run(SimConfig(n_vehicles=20, duration=2.5, seed=4), PROFILE).summary
    b = run(SimConfig(n_vehicles=20, duration=2.5, seed=4), PROFILE).summary
    a.pop("wall_seconds"), b.pop("wall_seconds")
    assert a == b


def test_empty_channel_handshake_latency_matches_airtime():
    """On a quiet channel, latency ~ airtime of 13 frames + compute + channel access."""
    r = run(SimConfig(n_vehicles=8, duration=4.0, seed=2, handshake_profile="pq-mldsa"), PROFILE)
    ok = [h for h in r.handshakes if h["success"]]
    assert ok
    rc = RadioConfig()
    floor = sum(rc.airtime(f) + rc.ack_time for m in (7490, 7430, 38) for f in rc.fragments(m))
    for h in ok:
        assert h["frames"] == 13
        assert floor < h["latency"] < floor + 0.02


def test_same_direction_policy():
    sim = Simulation(
        SimConfig(n_vehicles=60, duration=3.0, seed=5, hs_policy="same_direction"), PROFILE
    )
    r = sim.run()
    assert r.handshakes
    assert all(
        sim.hw.direction[h["initiator"]] == sim.hw.direction[h["responder"]] for h in r.handshakes
    )


def test_more_vehicles_more_channel_load():
    lo = run(SimConfig(n_vehicles=10, duration=2.5, seed=1), PROFILE).summary
    hi = run(SimConfig(n_vehicles=80, duration=2.5, seed=1), PROFILE).summary
    assert hi["cbr_mean"] > lo["cbr_mean"]


def test_bsm_delivery_falls_with_distance():
    r = run(SimConfig(n_vehicles=15, duration=3.0, seed=6, handshake_profile=None), PROFILE)
    bins = {b["dist_lo"]: b for b in r.bsm_bins}
    assert bins[0]["pdr_radio"] > 0.95
    assert bins[400]["pdr_radio"] is None or bins[400]["pdr_radio"] < 0.2


@pytest.mark.skipif(not OQS, reason="real crypto mode uses liboqs")
def test_real_crypto_mode_agrees_with_model():
    from pathlib import Path

    from qsv2v.sim.profiles import load_or_measure

    prof = load_or_measure(Path("results/sim/crypto_profile.json"))
    cfg = dict(n_vehicles=10, duration=3.0, seed=3, handshake_profile="pq-mldsa")
    model = run(SimConfig(**cfg), prof)
    sim = Simulation(SimConfig(**cfg, crypto_mode="real"))
    real = sim.run()
    assert sim.crypto.keys_agreed >= 1
    fm = {h["frames"] for h in model.handshakes if h["success"]}
    fr = {h["frames"] for h in real.handshakes if h["success"]}
    assert fm == fr == {13}
    lm = np.median([h["latency"] for h in model.handshakes if h["success"]])
    lr = np.median([h["latency"] for h in real.handshakes if h["success"]])
    assert abs(lm - lr) / lm < 0.25


def test_done_when_10_to_200_vehicles_logged_to_csv(tmp_path, monkeypatch):
    """Phase 6 'done when': runs with 10-200 vehicles and logs metrics to CSV."""
    from qsv2v.sim import profiles

    monkeypatch.setattr(cli, "load_or_measure", lambda path, reps=15: PROFILE)
    assert profiles  # module stays importable
    rc = cli.main(
        ["--vehicles", "10", "200", "--handshake", "pq-mldsa", "--duration", "1.5",
         "--warmup", "0.5", "--out", str(tmp_path)]
    )  # fmt: skip
    assert rc == 0
    rows = list(csv.DictReader((tmp_path / "summary.csv").open()))
    assert [int(r["n_vehicles"]) for r in rows] == [10, 200]
    assert all(r["cbr_mean"] not in ("", None) for r in rows)
    assert (tmp_path / "handshakes.csv").exists() and (tmp_path / "bsm_pdr.csv").exists()
    bins = list(csv.DictReader((tmp_path / "bsm_pdr.csv").open()))
    assert len(bins) == 2 * 9
