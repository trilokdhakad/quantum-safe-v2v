"""Shared types for the attack demonstrations."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class AuthenticationError(Exception):
    """A protocol party rejected a message (a check from the paper failed)."""


class SimClock:
    """Deterministic clock for timestamps (seconds, 32-bit as in the papers)."""

    def __init__(self, start: int = 1_790_000_000):
        self.t = start

    def now(self) -> int:
        return self.t

    def advance(self, seconds: int = 1) -> int:
        self.t += seconds
        return self.t


def ts_bytes(t: int) -> bytes:
    return int(t).to_bytes(4, "big")


@dataclass
class AttackResult:
    """Outcome of one attack: what was recovered versus the victim's true value."""

    paper: str
    attack: str
    claim_refuted: str
    adversary: str
    recovered: dict[str, str] = field(default_factory=dict)
    expected: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    @property
    def success(self) -> bool:
        return bool(self.expected) and all(
            self.recovered.get(k) == v for k, v in self.expected.items()
        )

    def report(self) -> str:
        lines = [
            f"[{self.paper}] {self.attack}",
            f"  refutes : {self.claim_refuted}",
            f"  attacker: {self.adversary}",
        ]
        for k, v in self.expected.items():
            got = self.recovered.get(k, "<not recovered>")
            mark = "MATCH" if got == v else "MISMATCH"
            lines.append(f"  {k}:")
            lines.append(f"    recovered: {_short(got)}")
            lines.append(f"    victim   : {_short(v)}   [{mark}]")
        lines.extend(f"  note: {n}" for n in self.notes)
        lines.append(
            f"  result  : {'SUCCESS' if self.success else 'FAILED'} ({self.elapsed_s:.3f} s)"
        )
        return "\n".join(lines)


def _short(s: str, n: int = 72) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.perf_counter() - self.t0
