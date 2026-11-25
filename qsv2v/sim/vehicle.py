"""Per-vehicle state and the two crypto back-ends used by the simulator.

Each vehicle has:

* a radio: a SimPy PriorityResource, so its frames go out one at a time and
  safety messages (priority 0) overtake handshake frames (priority 1), as
  802.11p's access categories do;
* a crypto processor: a FIFO queue tracked arithmetically (``busy_until``).
  Signing, verifying every received safety message, and each handshake step
  all wait their turn on it, so verification backlog is part of the result.
  ``cpu_slowdown`` scales the measured laptop times (e.g. 10-30x for an
  embedded on-board unit).

Crypto back-ends:

* :class:`ModelCrypto` -- message sizes and compute times from a measured
  :class:`~qsv2v.sim.profiles.CryptoProfile` (fast; any number of vehicles).
* :class:`RealCrypto` -- runs the actual PQ-V2V-AKE and actually signs and
  verifies every safety message with real keys; sizes are the real encodings
  and compute times are measured live (small runs; validates ModelCrypto).
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

from qsv2v.sim.profiles import BroadcastProfile, HandshakeProfile


@dataclass
class VehicleState:
    idx: int
    radio: object  # simpy.PriorityResource
    busy_until: float = 0.0
    cpu_time: float = 0.0
    known_certs: set = field(default_factory=set)
    bsm_counter: int = 0


def cpu_delay(v: VehicleState, now: float, cost: float) -> float:
    """Queue ``cost`` seconds of work on v's processor; return the wait until it is done."""
    start = max(now, v.busy_until)
    v.busy_until = start + cost
    v.cpu_time += cost
    return v.busy_until - now


class ModelCrypto:
    mode = "model"

    def __init__(self, hs: HandshakeProfile | None, bc: BroadcastProfile, slowdown: float):
        self.hs, self.bc, self.k = hs, bc, slowdown

    # Safety messages ---------------------------------------------------------
    def bsm_sign(self, i: int, with_cert: bool, now: float):
        size = self.bc.msg_cert_bytes if with_cert else self.bc.msg_digest_bytes
        return size, self.k * self.bc.t_sign, None

    def bsm_verify(self, sender: int, receiver: int, wire, with_cert: bool, knows_cert: bool, now):
        """Return (cost seconds, accepted, learned_cert)."""
        if with_cert:
            cost = self.bc.t_verify + (0.0 if knows_cert else self.bc.t_verify_cert)
            return self.k * cost, True, True
        if not knows_cert:
            return 0.0, False, False  # cannot verify: certificate not yet received
        return self.k * self.bc.t_verify, True, False

    # Handshakes -----------------------------------------------------------------
    def hs_start(self, i: int, j: int, now: float):
        return {"m1": self.hs.m1_bytes}, self.k * self.hs.t_initiate

    def hs_respond(self, state, now):
        state["m2"] = self.hs.m2_bytes
        return state["m2"], self.k * self.hs.t_respond

    def hs_finish(self, state, now):
        state["m3"] = self.hs.m3_bytes
        return state["m3"], self.k * self.hs.t_finish

    def hs_confirm(self, state, now):
        return True, self.k * self.hs.t_confirm


class RealCrypto:
    """Real PQ-V2V-AKE handshakes and real signed safety messages inside the simulation."""

    mode = "real"
    T0 = 1_790_000_000

    def __init__(self, n: int, hs_name: str | None, bc_name: str, slowdown: float, seed: int):
        from qsv2v.crypto.rng import DeterministicRNG
        from qsv2v.pqc import pq_v2v_ake as A
        from qsv2v.pqc.broadcast import Broadcaster, Receiver
        from qsv2v.pqc.certs import Authority, enroll_vehicle
        from qsv2v.pqc.sig import get_scheme
        from qsv2v.sim.profiles import BROADCAST_SETUPS, HANDSHAKE_SETUPS

        self.k = slowdown
        self.A = A
        self.net = None
        if hs_name:
            self.net = A.setup_network(
                n, seed=seed, n_pseudonyms=1, lifetime=10**7, **HANDSHAKE_SETUPS[hs_name]
            )
            self.net.clock.t = self.T0
        veh_alg, ca_alg = BROADCAST_SETUPS[bc_name]
        rng = DeterministicRNG(seed)
        ca_scheme = get_scheme(ca_alg, "oqs", rng.fork("bsm-ca"))
        ca = Authority(rng.fork("bsm-ca-rng"), ca_scheme)
        self.schemes = {veh_alg: get_scheme(veh_alg, "oqs", rng.fork("bsm-v"))}
        self.tx = []
        self.rx = []
        for i in range(n):
            sch = get_scheme(veh_alg, "oqs", rng.fork(f"bsm-{i}"))
            cred = enroll_vehicle(ca, b"VIN-%d" % i, sch, 1, self.T0, 10**7)[0]
            self.tx.append(Broadcaster(cred, sch, cert_every=10**9))  # cert choice made by sim
            self.rx.append(Receiver(ca.public_key, ca_scheme, self.schemes, max_age=10**6))
        self.keys_agreed = 0
        self.timings: dict[str, list[float]] = {}  # measured seconds per operation kind
        self._warm_up()

    def _warm_up(self) -> None:
        """Run each operation once untimed, as the measured profile does (median_ms warms up).

        Without this the first, cold handshake and signature (library set-up, first
        allocations) are charged to the simulation and bias real mode upwards.
        """
        from qsv2v.pqc.broadcast import Receiver, bsm_payload

        if self.net is not None and len(self.net.vehicles) >= 2:
            self.net.clock.t = self.T0
            self.A.handshake(self.net.vehicles[0], self.net.vehicles[1], self.net.clock)
        if self.tx:
            m = self.tx[0].sign(bsm_payload(0), self.T0, force_cert=True)
            r = self.rx[0]  # a throwaway receiver, so no real receiver caches this cert
            probe = Receiver(r.authority_pk, r.authority_scheme, self.schemes, max_age=10**6)
            probe.accept(m.encode(), self.T0)

    def _now(self, now: float) -> int:
        return self.T0 + int(now)

    def _record(self, kind: str, dt: float) -> float:
        self.timings.setdefault(kind, []).append(dt)
        return dt

    def _timed(self, kind: str, fn, *a):
        t0 = time.perf_counter()
        out = fn(*a)
        return out, self._record(kind, time.perf_counter() - t0)

    def observed_profile(self, base, hs_name: str | None, bc_name: str):
        """A model profile with the median costs this real run actually measured.

        Sizes come from ``base``. Running model mode with it checks that the two
        modes simulate the same thing, independent of how fast the CPU was.
        """
        from dataclasses import asdict, replace

        from qsv2v.sim.profiles import CryptoProfile

        med = {k: statistics.median(v) for k, v in self.timings.items()}
        hs = dict(base.handshakes)
        if hs_name:
            hs[hs_name] = asdict(replace(
                base.handshake(hs_name), t_initiate=med["initiate"], t_respond=med["respond"],
                t_finish=med["finish"], t_confirm=med["confirm"],
            ))  # fmt: skip
        b = base.broadcast(bc_name)
        t_verify = med.get("verify", b.t_verify)
        t_cert = med.get("verify_new_cert", t_verify + b.t_verify_cert) - t_verify
        bc = dict(base.broadcasts)
        bc[bc_name] = asdict(replace(b, t_sign=med.get("sign", b.t_sign), t_verify=t_verify,
                                     t_verify_cert=max(0.0, t_cert)))  # fmt: skip
        return CryptoProfile(base.machine + " (observed in real mode)", hs, bc)

    def bsm_sign(self, i: int, with_cert: bool, now: float):
        from qsv2v.pqc.broadcast import bsm_payload

        msg, dt = self._timed(
            "sign", lambda: self.tx[i].sign(bsm_payload(0), self._now(now), force_cert=with_cert)
        )
        wire = msg.encode()
        return len(wire), self.k * dt, wire

    def bsm_verify(self, sender: int, receiver: int, wire, with_cert: bool, knows_cert: bool, now):
        from qsv2v.pqc.broadcast import BroadcastError

        t0 = time.perf_counter()
        try:
            self.rx[receiver].accept(wire, self._now(now))
            ok = True
        except BroadcastError:
            ok = False
        dt = time.perf_counter() - t0
        if ok:
            self._record("verify_new_cert" if with_cert and not knows_cert else "verify", dt)
        return self.k * dt, ok, ok and with_cert

    def hs_start(self, i: int, j: int, now: float):
        self.net.clock.t = self._now(now)
        (m1, st), dt = self._timed(
            "initiate", self.A.initiate, self.net.vehicles[i], self.net.clock
        )
        return {"i": i, "j": j, "m1obj": m1, "st": st, "m1": len(m1.encode())}, self.k * dt

    def hs_respond(self, state, now):
        self.net.clock.t = self._now(now)
        (m2, st_r), dt = self._timed(
            "respond", self.A.respond, self.net.vehicles[state["j"]], state["m1obj"], self.net.clock
        )
        state.update(m2obj=m2, st_r=st_r, m2=len(m2.encode()))
        return state["m2"], self.k * dt

    def hs_finish(self, state, now):
        self.net.clock.t = self._now(now)
        (m3, res_i), dt = self._timed(
            "finish",
            self.A.finish,
            self.net.vehicles[state["i"]],
            state["st"],
            state["m2obj"],
            self.net.clock,
        )
        state.update(m3obj=m3, res_i=res_i, m3=len(m3.encode()))
        return state["m3"], self.k * dt

    def hs_confirm(self, state, now):
        res_r, dt = self._timed("confirm", self.A.confirm, state["st_r"], state["m3obj"])
        ok = res_r.key == state["res_i"].key
        self.keys_agreed += ok
        return ok, self.k * dt
