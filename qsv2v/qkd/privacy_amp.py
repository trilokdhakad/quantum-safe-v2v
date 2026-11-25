"""Privacy amplification and key verification with Toeplitz hashing over GF(2).

A Toeplitz matrix T (m x n) is fixed by its first column and first row, i.e. by
n + m - 1 random bits s:  T[i, j] = s[i - j + n - 1].  The family {x -> T x} is
2-universal, so by the leftover hash lemma, hashing a key about which Eve has
min-entropy H down to m <= H - 2 log2(1/eps) bits leaves Eve eps-close to
ignorant of the output.

T x is a convolution: (T x)[i] = (s * x)[i + n - 1], so it is computed with an
FFT in O((n + m) log(n + m)) rather than O(n m).
"""

from __future__ import annotations

import numpy as np

_FFT_THRESHOLD = 64  # below this, direct convolution is faster and exact


def toeplitz_matrix(seed_bits: np.ndarray, n: int, m: int) -> np.ndarray:
    """Explicit m x n Toeplitz matrix (for tests and small cases)."""
    s = np.asarray(seed_bits, dtype=np.uint8)
    if s.size != n + m - 1:
        raise ValueError("seed must have n + m - 1 bits")
    i = np.arange(m)[:, None]
    j = np.arange(n)[None, :]
    return s[i - j + n - 1]


def _convolve_counts(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Integer linear convolution of two 0/1 vectors."""
    if min(a.size, b.size) < _FFT_THRESHOLD:
        return np.convolve(a.astype(np.int64), b.astype(np.int64))
    size = a.size + b.size - 1
    nfft = 1 << (size - 1).bit_length()
    c = np.fft.irfft(np.fft.rfft(a, nfft) * np.fft.rfft(b, nfft), nfft)[:size]
    # Sums are integers <= min(len): float64 FFT error is far below 0.5 here.
    return np.rint(c).astype(np.int64)


def toeplitz_hash(key: np.ndarray, seed_bits: np.ndarray, out_len: int) -> np.ndarray:
    """Compress ``key`` (n bits) to ``out_len`` bits with the Toeplitz matrix of ``seed_bits``."""
    x = np.asarray(key, dtype=np.uint8)
    n, m = x.size, out_len
    if m < 0:
        raise ValueError("out_len must be non-negative")
    if m == 0 or n == 0:
        return np.zeros(m, dtype=np.uint8)
    s = np.asarray(seed_bits, dtype=np.uint8)
    if s.size != n + m - 1:
        raise ValueError("seed must have n + m - 1 bits")
    conv = _convolve_counts(s, x)
    return (conv[n - 1 : n - 1 + m] & 1).astype(np.uint8)


def random_seed_bits(n: int, m: int, rng: np.random.Generator) -> np.ndarray:
    """Public random seed for an m x n Toeplitz matrix."""
    return rng.integers(0, 2, size=max(n + m - 1, 0), dtype=np.uint8)


def privacy_amplify(
    key: np.ndarray, out_len: int, rng: np.random.Generator
) -> tuple[np.ndarray, np.ndarray]:
    """Hash ``key`` to ``out_len`` bits with a fresh public seed; returns (key, seed)."""
    seed = random_seed_bits(len(key), out_len, rng)
    return toeplitz_hash(key, seed, out_len), seed


def verification_tag(key: np.ndarray, seed_bits: np.ndarray, tag_bits: int = 64) -> np.ndarray:
    """Short universal-hash tag used to confirm Alice and Bob hold the same key."""
    return toeplitz_hash(key, seed_bits, tag_bits)
