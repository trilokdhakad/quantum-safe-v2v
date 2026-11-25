"""NIST P-256 (secp256r1) group arithmetic via the ``ecdsa`` package.

The base papers write ECC as scalar multiplication k.P and point addition on a
generic curve E_q(u, v) with base point G. We use P-256 throughout; none of the
attacks in this project depend on the curve (they exploit protocol algebra,
not the discrete-log problem).
"""

from __future__ import annotations

import hashlib

from ecdsa import NIST256p
from ecdsa.ellipticcurve import PointJacobi

CURVE = NIST256p
G: PointJacobi = NIST256p.generator
Q: int = NIST256p.order  # prime group order (the papers' q / p)
_COORD = 32


def point_bytes(p) -> bytes:
    """Uncompressed encoding x || y (64 bytes). Used inside hashes for '||'."""
    return int(p.x()).to_bytes(_COORD, "big") + int(p.y()).to_bytes(_COORD, "big")


def point_from_bytes(b: bytes) -> PointJacobi:
    if len(b) != 2 * _COORD:
        raise ValueError("expected 64-byte uncompressed point")
    x = int.from_bytes(b[:_COORD], "big")
    y = int.from_bytes(b[_COORD:], "big")
    if not CURVE.curve.contains_point(x, y):
        raise ValueError("point not on curve")
    return PointJacobi(CURVE.curve, x, y, 1, Q)


def x_bytes(p) -> bytes:
    """The papers' X_x: the x-coordinate."""
    return int(p.x()).to_bytes(_COORD, "big")


def y_bytes(p) -> bytes:
    """The papers' X_y: the y-coordinate."""
    return int(p.y()).to_bytes(_COORD, "big")


def hash_to_scalar(*parts: bytes) -> int:
    """h(...) interpreted as an integer mod q (for equations in Z_q)."""
    return int.from_bytes(hashlib.sha256(b"".join(parts)).digest(), "big") % Q
