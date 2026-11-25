"""Highway mobility: a multi-lane, two-direction ring road.

The road is a ring of length L (default 2 km), so vehicles leaving one end
re-enter at the other and density stays constant: it behaves like an endless
highway segment without edge effects. Each direction has ``lanes`` lanes; each
lane has its own mean speed and every vehicle keeps a constant speed drawn
around it (no lane changes in this model). Opposite-direction traffic closes at
the sum of the two speeds, so neighbours keep appearing and disappearing:
that is what makes handshake cost matter.

Positions are analytic, x(t) = (x0 + v t) mod L, so they can be evaluated at
any instant without stepping.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class HighwayConfig:
    length: float = 2000.0  # m
    lanes: int = 3  # per direction
    lane_width: float = 3.5  # m
    median: float = 4.0  # m between the two directions
    lane_speeds: tuple = (25.0, 30.0, 35.0)  # m/s per lane (90, 108, 126 km/h)
    speed_sd: float = 2.0  # m/s


class Highway:
    def __init__(self, n: int, cfg: HighwayConfig, rng: np.random.Generator):
        if n < 1:
            raise ValueError("need at least one vehicle")
        if len(cfg.lane_speeds) != cfg.lanes:
            raise ValueError("one mean speed per lane")
        self.n, self.cfg = n, cfg
        self.direction = np.where(np.arange(n) % 2 == 0, 1, -1)  # alternate directions
        self.lane = rng.integers(0, cfg.lanes, size=n)
        speed = np.asarray(cfg.lane_speeds)[self.lane] + rng.normal(0, cfg.speed_sd, size=n)
        self.speed = np.clip(speed, 5.0, None)
        self.v = self.direction * self.speed  # signed velocity along the road
        self.x0 = rng.uniform(0, cfg.length, size=n)
        # Lateral position: direction +1 on one side of the median, -1 on the other.
        offset = cfg.median / 2 + (self.lane + 0.5) * cfg.lane_width
        self.y = self.direction * offset

    def x(self, t: float) -> np.ndarray:
        return np.mod(self.x0 + self.v * t, self.cfg.length)

    def distances_from(self, i: int, t: float) -> np.ndarray:
        """Distance (m) from vehicle i to every vehicle at time t, along the ring."""
        x = self.x(t)
        dx = np.abs(x - x[i])
        dx = np.minimum(dx, self.cfg.length - dx)
        return np.hypot(dx, self.y - self.y[i])

    def distance(self, i: int, j: int, t: float) -> float:
        x = self.x(t)
        dx = abs(x[i] - x[j])
        dx = min(dx, self.cfg.length - dx)
        return float(np.hypot(dx, self.y[i] - self.y[j]))

    def density_per_km_lane(self) -> float:
        return self.n / (self.cfg.length / 1000) / (2 * self.cfg.lanes)
