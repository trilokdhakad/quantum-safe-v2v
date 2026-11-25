"""Cascade error reconciliation (Brassard & Salvail, 1993).

Bob corrects his sifted key to match Alice's using parities that Alice
discloses over the authenticated classical channel.

* Pass 1 splits the key into blocks of k1 = ceil(0.73 / Q); later passes double
  the block size and use a fresh public random permutation.
* For each block whose parities differ, a binary search (BINARY) locates and
  flips one error, disclosing one sub-block parity per halving.
* Cascade effect: flipping bit x changes the parity of the blocks containing x
  in every earlier pass. Those blocks now have odd parity and are searched
  too, which in turn may reveal more errors.

Leakage accounting: every parity Alice discloses counts as one leaked bit,
including top-level block parities and every binary-search step. Parities of
sub-blocks disclosed twice are counted twice, so the count is an upper bound.

Simulation shortcut: Bob compares Alice's disclosed parity with his own; we
compute the same comparison as the parity of ``alice XOR bob`` over the block.
Bob never reads Alice's bits directly, only one parity per disclosed block.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np


@dataclass
class CascadeResult:
    corrected: np.ndarray
    leaked_bits: int
    block_sizes: list[int]
    errors_corrected: int
    parity_mismatches_per_pass: list[int] = field(default_factory=list)

    @property
    def passes(self) -> int:
        return len(self.block_sizes)


def initial_block_size(qber: float, min_qber: float = 0.01) -> int:
    """k1 = ceil(0.73 / Q), with Q floored so a zero estimate stays usable."""
    return max(1, math.ceil(0.73 / max(qber, min_qber)))


def cascade(
    alice: np.ndarray,
    bob: np.ndarray,
    qber: float,
    rng: np.random.Generator,
    passes: int = 4,
    k1: int | None = None,
    min_qber: float = 0.01,
) -> CascadeResult:
    """Reconcile Bob's key with Alice's. Returns Bob's corrected key and leakage."""
    alice = np.asarray(alice, dtype=np.uint8)
    bob = np.asarray(bob, dtype=np.uint8).copy()
    if alice.shape != bob.shape or alice.ndim != 1:
        raise ValueError("keys must be one-dimensional and of equal length")
    if passes < 1:
        raise ValueError("passes must be at least 1")
    n = alice.size
    if n == 0:
        return CascadeResult(bob, 0, [], 0)

    k1 = k1 or initial_block_size(qber, min_qber)
    diff = alice ^ bob  # 1 where Bob is wrong (simulation bookkeeping only)
    leaked = 0
    corrected = 0
    perms: list[np.ndarray] = []  # perms[p][j] = key index at position j of pass p
    where: list[np.ndarray] = []  # where[p][i] = position of key index i in pass p
    sizes: list[int] = []
    mismatch: list[np.ndarray] = []  # odd-parity flag per block per pass
    first_mismatches: list[int] = []

    def block_indices(p: int, b: int) -> np.ndarray:
        k = sizes[p]
        return perms[p][b * k : (b + 1) * k]

    def binary_search(idx: np.ndarray) -> int:
        nonlocal leaked
        while idx.size > 1:
            half = (idx.size + 1) // 2
            left = idx[:half]
            leaked += 1  # Alice discloses the parity of the left half
            idx = left if diff[left].sum() & 1 else idx[half:]
        return int(idx[0])

    for p in range(passes):
        k = min(n, k1 * 2**p)
        perm = np.arange(n) if p == 0 else rng.permutation(n)
        pos = np.empty(n, dtype=np.int64)
        pos[perm] = np.arange(n)
        starts = np.arange(0, n, k)
        odd = (np.add.reduceat(diff[perm].astype(np.int64), starts) & 1).astype(bool)
        leaked += starts.size  # one parity per block
        perms.append(perm)
        where.append(pos)
        sizes.append(k)
        mismatch.append(odd)
        first_mismatches.append(int(odd.sum()))

        stack = [(p, int(b)) for b in np.flatnonzero(odd)]
        while stack:
            q, b = stack.pop()
            if not mismatch[q][b]:
                continue  # already fixed by another correction
            x = binary_search(block_indices(q, b))
            bob[x] ^= 1
            diff[x] ^= 1
            corrected += 1
            # Every block containing x, in every pass so far, flips parity.
            for r in range(p + 1):
                blk = int(where[r][x] // sizes[r])
                mismatch[r][blk] = not mismatch[r][blk]
                if mismatch[r][blk]:
                    stack.append((r, blk))

    return CascadeResult(bob, leaked, sizes, corrected, first_mismatches)
