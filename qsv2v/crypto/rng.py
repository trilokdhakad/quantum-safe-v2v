"""Seeded deterministic random source for reproducible protocol runs.

SHA-256 in counter mode. It exists so that every protocol transcript and
attack demo in this project is reproducible from a seed; it is a simulation
tool, not a production DRBG.
"""

from __future__ import annotations

import hashlib


class DeterministicRNG:
    def __init__(self, seed: int | bytes | str = 0):
        if isinstance(seed, int):
            seed = seed.to_bytes(16, "big", signed=True)
        elif isinstance(seed, str):
            seed = seed.encode()
        self._key = hashlib.sha256(b"qsv2v-drbg" + seed).digest()
        self._counter = 0

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            block = hashlib.sha256(self._key + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
            out += block
        return bytes(out[:n])

    def randbelow(self, n: int) -> int:
        """Uniform integer in [0, n) by rejection sampling."""
        if n <= 0:
            raise ValueError("n must be positive")
        k = (n.bit_length() + 7) // 8 + 8  # 64 extra bits: negligible bias anyway
        while True:
            v = int.from_bytes(self.bytes(k), "big")
            limit = (1 << (8 * k)) - ((1 << (8 * k)) % n)
            if v < limit:
                return v % n

    def scalar(self, q: int) -> int:
        """Uniform non-zero scalar in Z_q^*."""
        return 1 + self.randbelow(q - 1)

    def choice(self, seq):
        return seq[self.randbelow(len(seq))]

    def fork(self, label: str) -> DeterministicRNG:
        """Independent child stream (e.g. one per protocol party)."""
        return DeterministicRNG(self.bytes(32) + label.encode())
