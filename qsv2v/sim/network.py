"""V2V network simulation (SimPy): mobility + radio + safety messages + handshakes.

Every vehicle broadcasts a signed safety message ``bsm_rate`` times a second
(full certificate every ``cert_every``-th message, digest otherwise). Receivers
verify each message on their crypto processor. When a vehicle has verified a
neighbour's certificate and the two are within ``hs_range``, the lower-indexed
vehicle starts a PQ-V2V-AKE handshake with it (each pair at most once per run;
``hs_fraction`` < 1 makes only some pairs need a session; ``hs_policy`` =
"same_direction" limits sessions to vehicles travelling the same way, as
platooning or cooperative lane changes would).

Measured per run (after a warm-up):

* handshakes: success rate, latency (start -> responder confirmed), failure
  cause, frames and retries per handshake;
* safety messages: delivery ratio by distance (delivered AND verified), end-to-end
  latency (generated -> verified), share verified within the 100 ms budget,
  messages that could not be verified for lack of a certificate;
* channel busy ratio (sampled), collisions, retries, bytes on air;
* crypto-processor utilisation per vehicle.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

import numpy as np
import simpy

from qsv2v.sim.mobility import Highway, HighwayConfig
from qsv2v.sim.profiles import CryptoProfile
from qsv2v.sim.radio import Medium, RadioConfig
from qsv2v.sim.vehicle import ModelCrypto, RealCrypto, VehicleState, cpu_delay

BSM_PRIORITY, HS_PRIORITY = 0, 1
DIST_BINS = np.arange(0, 451, 50)


@dataclass(frozen=True)
class SimConfig:
    n_vehicles: int = 50
    duration: float = 6.0  # simulated seconds, including warm-up
    warmup: float = 1.0
    seed: int = 0
    bsm_rate: float = 10.0
    bsm_profile: str = "falcon"
    cert_every: int = 10
    handshake_profile: str | None = "pq-mldsa"
    hs_range: float = 200.0
    hs_fraction: float = 1.0
    hs_policy: str = "all"  # "all" neighbours, or "same_direction" (platooning-style)
    hs_timeout: float = 0.5
    latency_budget: float = 0.1
    cpu_slowdown: float = 1.0
    crypto_mode: str = "model"  # or "real"
    cbr_sample_period: float = 0.005
    cbr_sample_vehicles: int = 20
    trace: bool = False  # record positions and events for an animated replay
    trace_period: float = 0.05
    highway: HighwayConfig = field(default_factory=HighwayConfig)
    radio: RadioConfig = field(default_factory=RadioConfig)


@dataclass
class SimResult:
    config: SimConfig
    summary: dict
    handshakes: list[dict]
    bsm_bins: list[dict]
    trace: dict | None = None


class Simulation:
    def __init__(self, cfg: SimConfig, profile: CryptoProfile | None = None):
        self.cfg = cfg
        self.env = simpy.Environment()
        self.rng = np.random.default_rng(cfg.seed)
        self.hw = Highway(cfg.n_vehicles, cfg.highway, self.rng)
        self.medium = Medium(self.env, self.hw, cfg.radio, self.rng)
        self.v = [
            VehicleState(i, simpy.PriorityResource(self.env, 1)) for i in range(cfg.n_vehicles)
        ]
        if cfg.crypto_mode == "real":
            self.crypto = RealCrypto(
                cfg.n_vehicles, cfg.handshake_profile, cfg.bsm_profile, cfg.cpu_slowdown, cfg.seed
            )
        elif cfg.crypto_mode == "model":
            if profile is None:
                raise ValueError("model crypto needs a CryptoProfile")
            hs = profile.handshake(cfg.handshake_profile) if cfg.handshake_profile else None
            self.crypto = ModelCrypto(hs, profile.broadcast(cfg.bsm_profile), cfg.cpu_slowdown)
        else:
            raise ValueError("crypto_mode must be 'model' or 'real'")
        self.pairs: dict[tuple[int, int], str] = {}
        self.handshakes: list[dict] = []
        nb = len(DIST_BINS) - 1
        self.bsm_attempts = np.zeros(nb, int)
        self.bsm_delivered = np.zeros(nb, int)
        self.bsm_radio_ok = np.zeros(nb, int)  # all fragments received (before verification)
        self.bsm_on_time = np.zeros(nb, int)
        self.bsm_latency: list[float] = []
        self.bsm_unverifiable = 0
        self.bsm_sent = 0
        self.cbr_samples: list[float] = []
        self.trace_events: list[dict] = []

    # -- messaging -----------------------------------------------------------
    def _send(self, sender: int, size: int, dest: int | None, priority: int):
        """Send a (possibly fragmented) message; returns (receivers, frames, attempts)."""
        rx_all, frames, attempts = None, 0, 0
        for frag in self.cfg.radio.fragments(size):
            with self.v[sender].radio.request(priority=priority) as req:
                yield req
                rx, att = yield from self.medium.send_frame(sender, frag, dest)
            frames += 1
            attempts += att
            rx = set(int(r) for r in rx)
            rx_all = rx if rx_all is None else rx_all & rx
            if not rx_all:
                break
        return (rx_all or set()), frames, attempts

    # -- safety messages -------------------------------------------------------
    def bsm_loop(self, i: int):
        cfg, env, vi = self.cfg, self.env, self.v[i]
        period = 1.0 / cfg.bsm_rate
        yield env.timeout(float(self.rng.uniform(0, period)))
        while True:
            gen = env.now
            with_cert = vi.bsm_counter % cfg.cert_every == 0
            vi.bsm_counter += 1
            size, cost, wire = self.crypto.bsm_sign(i, with_cert, gen)
            yield env.timeout(cpu_delay(vi, env.now, cost))
            d0 = self.hw.distances_from(i, gen)
            counted = gen >= cfg.warmup
            if counted:
                self.bsm_sent += 1
                in_bins = np.digitize(d0[d0 > 0], DIST_BINS) - 1
                in_bins = in_bins[(in_bins >= 0) & (in_bins < len(self.bsm_attempts))]
                np.add.at(self.bsm_attempts, in_bins, 1)
            receivers, _, _ = yield from self._send(i, size, None, BSM_PRIORITY)
            if cfg.trace:
                self.trace_events.append(
                    {
                        "t": round(gen, 4),
                        "type": "bsm",
                        "a": i,
                        "cert": bool(with_cert),
                        "rx": len(receivers),
                    }
                )
            for r in receivers:
                self._deliver_bsm(i, r, wire, with_cert, gen, d0[r], counted)
            next_t = gen + period
            if next_t > env.now:
                yield env.timeout(next_t - env.now)

    def _deliver_bsm(self, s, r, wire, with_cert, gen, dist, counted):
        vr = self.v[r]
        if counted:
            b0 = int(np.digitize(dist, DIST_BINS)) - 1
            if 0 <= b0 < len(self.bsm_radio_ok):
                self.bsm_radio_ok[b0] += 1
        knows = s in vr.known_certs
        cost, ok, learned = self.crypto.bsm_verify(s, r, wire, with_cert, knows, self.env.now)
        if not ok:
            if counted:
                self.bsm_unverifiable += 1
            return
        if learned:
            vr.known_certs.add(s)
        done = self.env.now + cpu_delay(vr, self.env.now, cost)
        if counted:
            b = int(np.digitize(dist, DIST_BINS)) - 1
            if 0 <= b < len(self.bsm_delivered):
                self.bsm_delivered[b] += 1
                lat = done - gen
                self.bsm_on_time[b] += lat <= self.cfg.latency_budget
                self.bsm_latency.append(lat)
        self._maybe_handshake(r, s)

    # -- handshakes -------------------------------------------------------------
    def _maybe_handshake(self, r: int, s: int):
        cfg = self.cfg
        if cfg.handshake_profile is None or r > s:
            return  # the lower-indexed vehicle initiates
        pair = (r, s)
        if pair in self.pairs:
            return
        if self.hw.distance(r, s, self.env.now) > cfg.hs_range:
            return
        if cfg.hs_policy == "same_direction" and self.hw.direction[r] != self.hw.direction[s]:
            self.pairs[pair] = "skipped"
            return
        if self.rng.random() >= cfg.hs_fraction:
            self.pairs[pair] = "skipped"
            return
        self.pairs[pair] = "pending"
        self.env.process(self.handshake(r, s))

    def handshake(self, i: int, j: int):
        env, cfg, c = self.env, self.cfg, self.crypto
        start = env.now
        rec = {"initiator": i, "responder": j, "start": start, "frames": 0, "attempts": 0,
               "distance_start": self.hw.distance(i, j, start), "t_key_initiator": None,
               "success": False, "reason": "", "end": None, "latency": None}  # fmt: skip

        if cfg.trace:
            self.trace_events.append({"t": round(start, 4), "type": "hs_start", "a": i, "b": j})

        def fail(reason):
            if cfg.trace:
                self.trace_events.append(
                    {"t": round(env.now, 4), "type": "hs_fail", "a": i, "b": j, "reason": reason}
                )
            rec.update(success=False, reason=reason, end=env.now, latency=env.now - start)
            self.pairs[(i, j)] = "failed"
            self.handshakes.append(rec)

        state, cost = c.hs_start(i, j, env.now)
        yield env.timeout(cpu_delay(self.v[i], env.now, cost))
        rx, f, a = yield from self._send(i, state["m1"], j, HS_PRIORITY)
        rec["frames"] += f
        rec["attempts"] += a
        if not rx:
            return fail("m1 lost")
        try:
            size2, cost = c.hs_respond(state, env.now)
        except Exception as e:  # real mode: responder rejected
            return fail(f"m1 rejected: {e}")
        yield env.timeout(cpu_delay(self.v[j], env.now, cost))
        rx, f, a = yield from self._send(j, size2, i, HS_PRIORITY)
        rec["frames"] += f
        rec["attempts"] += a
        if not rx:
            return fail("m2 lost")
        size3, cost = c.hs_finish(state, env.now)
        yield env.timeout(cpu_delay(self.v[i], env.now, cost))
        rec["t_key_initiator"] = env.now - start
        rx, f, a = yield from self._send(i, size3, j, HS_PRIORITY)
        rec["frames"] += f
        rec["attempts"] += a
        if not rx:
            return fail("m3 lost")
        ok, cost = c.hs_confirm(state, env.now)
        yield env.timeout(cpu_delay(self.v[j], env.now, cost))
        if not ok:
            return fail("key mismatch")
        latency = env.now - start
        if latency > cfg.hs_timeout:
            return fail("timeout")
        if cfg.trace:
            self.trace_events.append(
                {
                    "t": round(env.now, 4),
                    "type": "hs_ok",
                    "a": i,
                    "b": j,
                    "ms": round(1000 * latency, 2),
                }
            )
        rec.update(success=True, reason="", end=env.now, latency=latency)
        self.pairs[(i, j)] = "established"
        self.handshakes.append(rec)

    # -- channel busy ratio ----------------------------------------------------
    def cbr_sampler(self):
        k = min(self.cfg.cbr_sample_vehicles, self.cfg.n_vehicles)
        sample = self.rng.choice(self.cfg.n_vehicles, size=k, replace=False)
        while True:
            yield self.env.timeout(self.cfg.cbr_sample_period)
            if self.env.now >= self.cfg.warmup:
                now = self.env.now
                self.cbr_samples.append(
                    np.mean([self.medium.sensed_busy(int(i), now) for i in sample])
                )

    # -- run ----------------------------------------------------------------------
    def run(self) -> SimResult:
        t0 = time.perf_counter()
        for i in range(self.cfg.n_vehicles):
            self.env.process(self.bsm_loop(i))
        self.env.process(self.cbr_sampler())
        self.env.run(until=self.cfg.duration)
        wall = time.perf_counter() - t0
        return SimResult(
            self.cfg, self._summary(wall), self._hs_rows(), self._bsm_rows(),
            self._trace() if self.cfg.trace else None,
        )  # fmt: skip

    def _trace(self) -> dict:
        """Positions every ``trace_period`` and all events, for an animated replay."""
        cfg, hw = self.cfg, self.hw
        times = np.arange(0.0, cfg.duration + 1e-9, cfg.trace_period)
        return {
            "road_length": hw.cfg.length,
            "lanes": hw.cfg.lanes,
            "comm_range": cfg.radio.comm_range,
            "period": cfg.trace_period,
            "vehicles": [
                {
                    "id": i,
                    "dir": int(hw.direction[i]),
                    "lane": int(hw.lane[i]),
                    "y": round(float(hw.y[i]), 2),
                    "speed_kmh": round(float(hw.speed[i]) * 3.6, 1),
                }
                for i in range(hw.n)
            ],
            "x": [[round(float(v), 1) for v in hw.x(t)] for t in times],
            "events": self.trace_events,
        }

    def _hs_rows(self) -> list[dict]:
        return [h for h in self.handshakes if h["start"] >= self.cfg.warmup]

    def _bsm_rows(self) -> list[dict]:
        rows = []
        for b in range(len(self.bsm_attempts)):
            a = int(self.bsm_attempts[b])
            rows.append(
                {
                    "dist_lo": int(DIST_BINS[b]),
                    "dist_hi": int(DIST_BINS[b + 1]),
                    "attempts": a,
                    "received_radio": int(self.bsm_radio_ok[b]),
                    "delivered_verified": int(self.bsm_delivered[b]),
                    "on_time": int(self.bsm_on_time[b]),
                    "pdr_radio": round(self.bsm_radio_ok[b] / a, 4) if a else None,
                    "pdr": round(self.bsm_delivered[b] / a, 4) if a else None,
                    "pdr_on_time": round(self.bsm_on_time[b] / a, 4) if a else None,
                }
            )
        return rows

    def _summary(self, wall: float) -> dict:
        cfg = self.cfg
        hs = self._hs_rows()
        ok = [h for h in hs if h["success"]]
        lat = np.array([h["latency"] for h in ok]) * 1000
        reasons = {}
        for h in hs:
            if not h["success"]:
                key = h["reason"].split(":")[0]
                reasons[key] = reasons.get(key, 0) + 1
        bl = np.array(self.bsm_latency) * 1000
        within = slice(0, int(np.searchsorted(DIST_BINS, cfg.radio.comm_range)))
        near = slice(0, 2)  # 0-100 m
        span = cfg.duration - cfg.warmup
        cpu = np.array([v.cpu_time for v in self.v]) / cfg.duration
        st = self.medium.stats

        def pct(a, q):
            return round(float(np.percentile(a, q)), 3) if len(a) else None

        def ratio(num, den):
            return round(float(num) / float(den), 4) if den else None

        return {
            "n_vehicles": cfg.n_vehicles,
            "density_veh_per_km_lane": round(self.hw.density_per_km_lane(), 2),
            "handshake_profile": cfg.handshake_profile or "none",
            "bsm_profile": cfg.bsm_profile,
            "crypto_mode": cfg.crypto_mode,
            "cpu_slowdown": cfg.cpu_slowdown,
            "hs_fraction": cfg.hs_fraction,
            "hs_policy": cfg.hs_policy,
            "seed": cfg.seed,
            "sim_seconds": span,
            "hs_attempted": len(hs),
            "hs_succeeded": len(ok),
            "hs_success_rate": ratio(len(ok), len(hs)),
            "hs_per_second": round(len(hs) / span, 2),
            "hs_latency_ms_mean": round(float(lat.mean()), 3) if len(lat) else None,
            "hs_latency_ms_p50": pct(lat, 50),
            "hs_latency_ms_p95": pct(lat, 95),
            "hs_latency_ms_max": round(float(lat.max()), 3) if len(lat) else None,
            "hs_within_100ms": ratio((lat <= 100).sum(), len(hs)),
            "hs_frames_mean": round(float(np.mean([h["frames"] for h in hs])), 2) if hs else None,
            "hs_retries_mean": round(float(np.mean([h["attempts"] - h["frames"] for h in hs])), 2)
            if hs
            else None,
            "hs_fail_reasons": ";".join(f"{k}={v}" for k, v in sorted(reasons.items())),
            "bsm_sent": self.bsm_sent,
            "bsm_pdr_radio_in_range": ratio(
                self.bsm_radio_ok[within].sum(), self.bsm_attempts[within].sum()
            ),
            "bsm_pdr_0_100m": ratio(self.bsm_delivered[near].sum(), self.bsm_attempts[near].sum()),
            "bsm_pdr_in_range": ratio(
                self.bsm_delivered[within].sum(), self.bsm_attempts[within].sum()
            ),
            "bsm_on_time_in_range": ratio(
                self.bsm_on_time[within].sum(), self.bsm_attempts[within].sum()
            ),
            "bsm_latency_ms_mean": round(float(bl.mean()), 3) if len(bl) else None,
            "bsm_latency_ms_p95": pct(bl, 95),
            "bsm_unverifiable": self.bsm_unverifiable,
            "cbr_mean": round(float(np.mean(self.cbr_samples)), 4) if self.cbr_samples else None,
            "cbr_p95": pct(np.array(self.cbr_samples), 95),
            "cpu_util_mean": round(float(cpu.mean()), 4),
            "cpu_util_max": round(float(cpu.max()), 4),
            "frames": st.frames,
            "retries": st.retries,
            "unicast_drops": st.unicast_drops,
            "losses_collision": st.losses_collision,
            "losses_fading": st.losses_fading,
            "mbytes_on_air": round(st.bytes_on_air / 1e6, 3),
            "wall_seconds": round(wall, 2),
        }


def run(cfg: SimConfig, profile: CryptoProfile | None = None) -> SimResult:
    return Simulation(cfg, profile).run()


def config_dict(cfg: SimConfig) -> dict:
    return asdict(cfg)
