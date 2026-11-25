"""E6 -- Crypto timing: ms per operation for ECDSA, X25519, ML-KEM, ML-DSA and Falcon.

``qsv2v.pqc.bench.primitive_table`` (median of many real operations; liboqs for
the post-quantum schemes, ``cryptography`` for ECDSA and X25519) is repeated
several times; the table reports the mean of the medians with a 95% CI.
Laptop only: no Raspberry Pi was available.
"""

from __future__ import annotations

import platform
from pathlib import Path

from qsv2v.experiments.common import (
    COLORS,
    Outcome,
    aggregate,
    figure,
    outdir,
    save,
    write_csv,
    write_outcome,
    write_table,
)

NAME = "e06_crypto_timing"
OPS = ["keygen", "sign", "verify", "encaps", "decaps"]


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    from qsv2v.pqc.bench import primitive_table

    d = outdir(base, NAME)
    repeats = 2 if quick else 7
    rows = []
    for k in range(repeats):
        for r in primitive_table(reps=20 if quick else 200):
            rows.append({**r, "repeat": k})
    log("  E6: done")
    write_csv(d / "data.csv", rows)
    # Group by operation only: Falcon signatures vary in length between repeats.
    summ = aggregate(rows, ["primitive", "kind", "operation"], ["ms"])
    for r in summ:
        same = [
            x for x in rows if (x["primitive"], x["operation"]) == (r["primitive"], r["operation"])
        ]
        r["bytes_pk"] = same[0].get("bytes_pk")
        outs = [x["bytes_out"] for x in same if x.get("bytes_out") is not None]
        r["bytes_out"] = max(outs) if outs else None  # largest seen (Falcon varies)
    summ.sort(key=lambda r: (r["kind"], r["primitive"], OPS.index(r["operation"])))
    write_csv(d / "summary.csv", summ)
    write_table(d / "table.md", summ, [
        ("primitive", "Primitive"), ("operation", "Operation"), ("ms±", "ms"),
        ("bytes_pk", "Public key (B)"), ("bytes_out", "Signature / ciphertext (B, max seen)"),
    ])  # fmt: skip
    (d / "machine.txt").write_text(f"{platform.platform()}\n{platform.processor()}\n"
                                   f"Python {platform.python_version()}\n", "utf-8")  # fmt: skip

    prims = list(dict.fromkeys(r["primitive"] for r in summ))
    fig, ax = figure(7.2, 3.9)
    width = 0.8 / len(prims)
    present = [op for op in OPS if any(r["operation"] == op for r in summ)]
    for i, p in enumerate(prims):
        ys, xs, es = [], [], []
        for j, op in enumerate(present):
            r = next((r for r in summ if r["primitive"] == p and r["operation"] == op), None)
            if r:
                ys.append(j + (i - (len(prims) - 1) / 2) * width)
                xs.append(r["ms"])
                es.append(r["ms_ci95"] if r["ms_ci95"] == r["ms_ci95"] else 0)
        ax.barh(ys, xs, xerr=es, height=width * 0.9, color=COLORS[i % len(COLORS)], label=p,
                error_kw={"lw": 0.8})  # fmt: skip
    ax.set_yticks(range(len(present)), present)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlabel("Milliseconds per operation (log scale)")
    ax.set_title("Cost of each cryptographic operation on this laptop")
    ax.legend(fontsize=8, loc="lower right")
    ax.grid(axis="y", visible=False)
    save(fig, d)

    def ms(p, op):
        return next((r["ms"] for r in summ if r["primitive"] == p and r["operation"] == op), None)

    ec_sv = max(ms("ECDSA-P256", "sign"), ms("ECDSA-P256", "verify"))
    pq_sigs = [p for p in prims if p in ("ML-DSA-44", "Falcon-512")]
    ratios = {p: max(ms(p, "sign"), ms(p, "verify")) / ec_sv for p in pq_sigs}
    sigs = [p for p in prims if ms(p, "sign")]
    sign_slower = {p: ms(p, "sign") >= ms(p, "verify") for p in sigs}
    sign_slowest = all(sign_slower.values())
    worst = max(summ, key=lambda r: r["ms"])
    same_order = all(v < 10 for v in ratios.values())
    return write_outcome(d, Outcome(
        "E6", "Crypto timing",
        "PQC is within the same order as ECC; signing is the slowest step",
        "Signing and verification: "
        + ", ".join(f"{p} {v:.1f}× ECDSA (slowest of sign/verify)" for p, v in ratios.items())
        + ". Signing slower than verifying: "
        + ", ".join(f"{p} {'yes' if v else 'no'} ({ms(p, 'sign'):.3f} vs {ms(p, 'verify'):.3f} ms)"
                    for p, v in sign_slower.items())
        + ". "
        f"Slowest operation overall: {worst['primitive']} {worst['operation']} "
        f"({worst['ms']:.2f} ms), done once per pseudonym, not per message.",
        True if same_order and sign_slowest else
        "partly" if same_order and all(sign_slower[p] for p in pq_sigs) else False,
        numbers={"pq_vs_ecdsa_sign_verify": ratios, "slowest": f"{worst['primitive']} "
                 f"{worst['operation']}", "slowest_ms": worst["ms"],
                 "median_ms": {f"{r['primitive']} {r['operation']}": r["ms"] for r in summ}},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
