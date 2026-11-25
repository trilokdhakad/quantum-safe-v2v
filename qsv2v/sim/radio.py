"""Shared 5.9 GHz radio channel: 802.11p airtime, CSMA/CA, collisions, retries.

Model (stated assumptions, all configurable in :class:`RadioConfig`):

* **Airtime.** 10 MHz 802.11p at 6 Mbit/s: a frame of n payload bytes lasts
  40 us (PHY preamble + header) + (n + 44 bytes MAC/LLC overhead) x 8 / 6e6.
  A 1,400-byte frame takes about 1.97 ms on air.
* **Fragmentation.** A message larger than ``frame_payload`` (1,400 B) is sent
  as ceil(size / 1400) back-to-back frames and is received only if every
  fragment is. (IEEE 1609.3 WSMP cannot actually carry more than ~1,400 B;
  fragmentation here is a hypothetical that prices oversized PQ messages.)
* **Channel access (CSMA/CA with EDCA).** Before each frame the sender waits
  until no transmission from a vehicle within ``cs_range`` is in progress, then
  AIFS plus a random backoff of 0..CW slots, and senses again. Two 802.11p
  access categories (IEEE 802.11 OCB defaults): safety messages use AC_VO
  (AIFSN 2, CW 3..7), handshake frames AC_BE (AIFSN 6, CW 15..1023), so safety
  messages win the channel more often.
* **Reception.** A receiver at distance d decodes with probability
  1 / (1 + exp((d - range) / width)) times (1 - extra_loss): about 99% at
  range/2, 50% at the nominal range. Independently, the frame is lost at a
  receiver if any other transmission overlapping it in time comes from a
  sender within ``interference_range`` of that receiver (this includes hidden
  terminals and the receiver's own transmissions: radios are half-duplex).
* **Unicast** frames are acknowledged; a lost frame is retried up to
  ``retry_limit`` times with the contention window doubling each time.
  **Broadcast** frames (safety messages) are never retried, as in 802.11.

Every transmission is logged, so channel busy ratio, collisions and retries
are measured, not assumed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from qsv2v.sim.mobility import Highway


@dataclass(frozen=True)
class RadioConfig:
    comm_range: float = 300.0  # m, 50% decode point
    fade_width: float = 30.0  # m, width of the decode-probability edge
    cs_range: float = 450.0  # m, carrier sense
    interference_range: float = 450.0  # m
    data_rate: float = 6e6  # bit/s
    frame_payload: int = 1400  # bytes per frame
    mac_overhead: int = 44  # bytes (MAC header, FCS, LLC/SNAP, WSMP)
    phy_overhead: float = 40e-6  # s
    slot: float = 13e-6
    sifs: float = 32e-6
    aifsn: int = 2  # AC_VO (safety messages)
    cw_min: int = 3
    cw_max: int = 7
    aifsn_be: int = 6  # AC_BE (handshakes)
    cw_min_be: int = 15
    cw_max_be: int = 1023
    retry_limit: int = 4
    ack_bytes: int = 14
    extra_loss: float = 0.0  # additional independent frame loss

    @property
    def difs(self) -> float:
        return self.sifs + self.aifsn * self.slot

    def access_params(self, best_effort: bool) -> tuple[float, int, int]:
        """(AIFS, CWmin, CWmax) for the access category."""
        if best_effort:
            return self.sifs + self.aifsn_be * self.slot, self.cw_min_be, self.cw_max_be
        return self.difs, self.cw_min, self.cw_max

    @property
    def ack_time(self) -> float:
        return self.sifs + self.phy_overhead + self.ack_bytes * 8 / self.data_rate

    def airtime(self, payload: int) -> float:
        return self.phy_overhead + (payload + self.mac_overhead) * 8 / self.data_rate

    def fragments(self, size: int) -> list[int]:
        n = max(1, math.ceil(size / self.frame_payload))
        sizes = [self.frame_payload] * (n - 1)
        sizes.append(size - self.frame_payload * (n - 1))
        return sizes

    def decode_prob(self, d: np.ndarray) -> np.ndarray:
        p = 1.0 / (1.0 + np.exp((d - self.comm_range) / self.fade_width))
        return p * (1.0 - self.extra_loss)


@dataclass
class Tx:
    sender: int
    start: float
    end: float  # includes the ACK exchange for unicast
    unicast: bool


@dataclass
class ChannelStats:
    frames: int = 0
    unicast_frames: int = 0
    retries: int = 0
    unicast_drops: int = 0
    airtime: float = 0.0
    bytes_on_air: int = 0
    losses_collision: int = 0  # unicast attempts lost to interference
    losses_fading: int = 0  # unicast attempts lost to distance / fading
    defers: int = 0


class Medium:
    """The shared channel. Use from SimPy processes via :meth:`send_frame`."""

    def __init__(self, env, highway: Highway, cfg: RadioConfig, rng: np.random.Generator):
        self.env, self.hw, self.cfg, self.rng = env, highway, cfg, rng
        self.log: list[Tx] = []  # recent transmissions (pruned)
        self.all_tx_count = 0
        self.stats = ChannelStats()
        self._max_frame = cfg.airtime(cfg.frame_payload) + cfg.ack_time

    # -- helpers ------------------------------------------------------------
    def _prune(self, now: float) -> None:
        horizon = now - 2 * self._max_frame
        if self.log and self.log[0].end < horizon:
            self.log = [t for t in self.log if t.end >= horizon]

    def busy_until(self, sender: int, now: float) -> float | None:
        """End time of the latest in-progress transmission the sender can hear, or None."""
        active = [t for t in self.log if t.start <= now < t.end and t.sender != sender]
        if not active:
            return None
        d = self.hw.distances_from(sender, now)
        heard = [t.end for t in active if d[t.sender] < self.cfg.cs_range]
        return max(heard) if heard else None

    def sensed_busy(self, i: int, now: float) -> bool:
        active = [t for t in self.log if t.start <= now < t.end]
        if not active:
            return False
        d = self.hw.distances_from(i, now)
        return any(t.sender == i or d[t.sender] < self.cfg.cs_range for t in active)

    def _received(self, tx: Tx, candidates: np.ndarray) -> np.ndarray:
        """Boolean mask over ``candidates``: who decoded this frame."""
        mid = 0.5 * (tx.start + tx.end)
        d = self.hw.distances_from(tx.sender, mid)[candidates]
        ok = self.rng.random(candidates.size) < self.cfg.decode_prob(d)
        others = [t for t in self.log if t is not tx and t.start < tx.end and t.end > tx.start]
        if others:
            x = self.hw.x(mid)
            cx, cy = x[candidates], self.hw.y[candidates]
            L = self.hw.cfg.length
            for o in others:
                dx = np.abs(cx - x[o.sender])
                dx = np.minimum(dx, L - dx)
                collided = np.hypot(dx, cy - self.hw.y[o.sender]) < self.cfg.interference_range
                ok &= ~collided
        return ok

    # -- frame transmission ----------------------------------------------------
    def _access(self, sender: int, cw: int, aifs: float):
        """CSMA/CA: wait for an idle medium, AIFS, and a random backoff."""
        while True:
            now = self.env.now
            busy = self.busy_until(sender, now)
            if busy is not None:
                self.stats.defers += 1
                yield self.env.timeout(busy - now + 1e-9)
                continue
            backoff = aifs + int(self.rng.integers(0, cw + 1)) * self.cfg.slot
            yield self.env.timeout(backoff)
            if self.busy_until(sender, self.env.now) is None:
                return

    def send_frame(
        self, sender: int, payload: int, dest: int | None = None, best_effort: bool | None = None
    ):
        """SimPy process. Returns (receivers, attempts).

        Broadcast (dest None): numpy array of receiver indices; 1 attempt, no retries.
        Unicast: [dest] if delivered within the retry limit, else []; attempts used.
        """
        cfg = self.cfg
        if best_effort is None:
            best_effort = dest is not None
        aifs, cw, cw_max = cfg.access_params(best_effort)
        attempts = 1 if dest is None else cfg.retry_limit + 1
        for attempt in range(attempts):
            yield from self._access(sender, cw, aifs)
            start = self.env.now
            dur = cfg.airtime(payload) + (cfg.ack_time if dest is not None else 0.0)
            tx = Tx(sender, start, start + dur, dest is not None)
            self._prune(start)
            self.log.append(tx)
            self.stats.frames += 1
            self.stats.airtime += dur
            self.stats.bytes_on_air += payload + cfg.mac_overhead
            if dest is not None:
                self.stats.unicast_frames += 1
                if attempt:
                    self.stats.retries += 1
            yield self.env.timeout(dur)
            if dest is None:
                d = self.hw.distances_from(sender, start)
                cand = np.flatnonzero((d < cfg.comm_range * 1.5) & (np.arange(self.hw.n) != sender))
                return cand[self._received(tx, cand)], 1
            got = self._received(tx, np.array([dest]))[0]
            if got:
                return [dest], attempt + 1
            # Classify the loss for statistics (fading vs interference).
            mid = 0.5 * (tx.start + tx.end)
            p = cfg.decode_prob(np.array([self.hw.distance(sender, dest, mid)]))[0]
            if p > 0.5:
                self.stats.losses_collision += 1
            else:
                self.stats.losses_fading += 1
            cw = min(2 * cw + 1, cw_max)
        self.stats.unicast_drops += 1
        return [], attempts
