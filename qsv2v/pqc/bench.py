"""Timing of every primitive (experiment E6) and of each PQ-V2V-AKE step.

All numbers are medians of real operations on this machine (liboqs for ML-KEM,
ML-DSA and Falcon when available; ``cryptography`` for ECDSA and X25519).

    python -m qsv2v.pqc.bench
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable


def median_ms(fn: Callable[[], object], reps: int) -> float:
    fn()  # warm up
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t0)
    return 1000 * statistics.median(ts)


def primitive_table(reps: int = 200) -> list[dict]:
    """ms per operation for each signature scheme and KEM (E6)."""
    from qsv2v.pqc.kem import MLKEM768, X25519KEM
    from qsv2v.pqc.sig import ECDSAP256, MLDSA44, Falcon512, oqs_available

    rows = []
    msg = b"m" * 200
    sigs = [ECDSAP256()]
    if oqs_available():
        sigs += [MLDSA44("oqs"), Falcon512()]
    else:
        sigs += [MLDSA44("dilithium-py")]
    for s in sigs:
        kp = s.keygen()
        sig = s.sign(kp.secret_key, msg)
        rows += [
            {"primitive": s.name, "kind": "signature", "operation": "keygen",
             "ms": median_ms(s.keygen, reps // 4)},
            {"primitive": s.name, "kind": "signature", "operation": "sign",
             "ms": median_ms(lambda s=s, kp=kp: s.sign(kp.secret_key, msg), reps)},
            {"primitive": s.name, "kind": "signature", "operation": "verify",
             "ms": median_ms(lambda s=s, kp=kp, sig=sig: s.verify(kp.public_key, msg, sig), reps)},
        ]  # fmt: skip
        rows[-1]["bytes_pk"] = rows[-2]["bytes_pk"] = rows[-3]["bytes_pk"] = len(kp.public_key)
        rows[-1]["bytes_out"] = rows[-2]["bytes_out"] = len(sig)
    kems = [X25519KEM(), MLKEM768("oqs" if oqs_available() else "kyber-py")]
    for k in kems:
        kp = k.keygen()
        ct, _ = k.encaps(kp.public_key)
        name = getattr(k, "name", "KEM")
        rows += [
            {"primitive": name, "kind": "kem", "operation": "keygen",
             "ms": median_ms(k.keygen, reps)},
            {"primitive": name, "kind": "kem", "operation": "encaps",
             "ms": median_ms(lambda k=k, kp=kp: k.encaps(kp.public_key), reps)},
            {"primitive": name, "kind": "kem", "operation": "decaps",
             "ms": median_ms(lambda k=k, kp=kp, ct=ct: k.decaps(kp.secret_key, ct), reps)},
        ]  # fmt: skip
        for r in rows[-3:]:
            r["bytes_pk"] = len(kp.public_key)
            r["bytes_out"] = len(ct)
    for r in rows:
        r["ms"] = round(r["ms"], 4)
    return rows


if __name__ == "__main__":
    for r in primitive_table():
        print(f"{r['primitive']:11s} {r['operation']:7s} {r['ms']:8.4f} ms")
