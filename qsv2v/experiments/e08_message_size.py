"""E8 -- Message size vs packet limit: bytes per signed safety message, per signature scheme.

Real signed safety messages (200-byte payload) built and verified by
``qsv2v.pqc.broadcast``: one carrying the full pseudonym certificate (sent every
10th message) and one carrying only the certificate digest. The usable frame is
1,400 bytes. ECDSA (raw r||s) and ML-DSA signatures have fixed length; Falcon-512
signatures vary by a few bytes, so the spread is measured over many messages and
the worst case uses the maximum length allowed by the scheme (liboqs).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from qsv2v.experiments.common import (
    COLORS,
    Outcome,
    figure,
    outdir,
    save,
    write_csv,
    write_outcome,
    write_table,
)

NAME = "e08_message_size"


def signature_spread(n: int) -> list[dict]:
    """Min / max signature length over n messages (Falcon signatures vary slightly)."""
    from qsv2v.crypto.rng import DeterministicRNG
    from qsv2v.pqc.sig import get_scheme, oqs_available

    rows = []
    be = "oqs" if oqs_available() else "dilithium-py"
    names = ["ECDSA-P256", "ML-DSA-44"] + (["Falcon-512"] if oqs_available() else [])
    for name in names:
        s = get_scheme(name, be, DeterministicRNG(1).fork(name))
        kp = s.keygen()
        lens = [len(s.sign(kp.secret_key, b"bsm-%d" % i)) for i in range(n)]
        rows.append({"scheme": name, "messages": n, "sig_min": min(lens), "sig_max": max(lens),
                     "sig_mean": float(np.mean(lens))})  # fmt: skip
    return rows


def max_signature_lengths() -> dict:
    """Largest signature each scheme can produce (liboqs metadata; ECDSA raw r||s)."""
    from qsv2v.pqc.sig import oqs_available

    out = {"ECDSA-P256": 64}
    if oqs_available():
        import oqs

        for name in ("ML-DSA-44", "Falcon-512"):
            with oqs.Signature(name) as s:
                out[name] = int(s.details["length_signature"])
    return out


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    from qsv2v.pqc.broadcast import FRAME_LIMIT, size_table
    from qsv2v.pqc.sig import oqs_available

    d = outdir(base, NAME)
    rows = size_table(sig_backend="oqs" if oqs_available() else "dilithium-py")
    spec_max = max_signature_lengths()
    for r in rows:
        r["frame_limit"] = FRAME_LIMIT
        mx = spec_max.get(r["vehicle_alg"], r["signature_bytes"])
        r["sig_max_bytes"] = mx
        r["msg_with_digest_worst_bytes"] = r["msg_with_digest_bytes"] - r["signature_bytes"] + mx
        r["frames_with_cert"] = -(-r["msg_with_cert_bytes"] // FRAME_LIMIT)
        r["frames_with_digest"] = -(-r["msg_with_digest_bytes"] // FRAME_LIMIT)
    write_csv(d / "data.csv", rows)
    spread = signature_spread(20 if quick else 500)
    write_csv(d / "signature_lengths.csv", spread)
    write_csv(d / "summary.csv", rows)
    write_table(d / "table.md", rows, [
        ("config", "Configuration"), ("signature_bytes", "Signature (B)"),
        ("cert_bytes", "Certificate (B)"), ("msg_with_digest_bytes", "Message + digest (B)"),
        ("msg_with_digest_worst_bytes", "Worst case + digest (B)"),
        ("msg_with_cert_bytes", "Message + certificate (B)"),
        ("avg_bytes_per_msg", "Average at 1 cert / 10 msgs (B)"),
        ("frames_with_digest", "Frames (digest)"), ("frames_with_cert", "Frames (cert)"),
    ])  # fmt: skip
    log("  E8: done")

    fig, ax = figure(7.4, 3.4)
    labels = [r["config"] for r in rows][::-1]
    y = np.arange(len(rows))
    dig = [r["msg_with_digest_bytes"] for r in rows][::-1]
    cert = [r["msg_with_cert_bytes"] for r in rows][::-1]
    ax.barh(y + 0.19, dig, height=0.36, color=COLORS[0], label="With certificate digest (9 of 10)")
    ax.barh(y - 0.19, cert, height=0.36, color=COLORS[1], label="With full certificate (1 of 10)")
    for yy, a, b in zip(y, dig, cert, strict=True):
        ax.text(a + 60, yy + 0.19, f"{a:,} B", va="center", fontsize=7.5)
        ax.text(b + 60, yy - 0.19, f"{b:,} B", va="center", fontsize=7.5)
    ax.axvline(FRAME_LIMIT, color="#555", ls="--", lw=1, label="1,400 B frame limit")
    ax.set_yticks(y, labels)
    ax.set_xlim(0, max(cert) * 1.18)
    ax.set_xlabel("Bytes on air per signed safety message (200 B payload)")
    ax.set_title("Only ECDSA and Falcon-512 + digest fit one frame")
    ax.legend(fontsize=8, loc="upper right")
    ax.tick_params(axis="y", labelsize=8)
    ax.grid(axis="y", visible=False)
    save(fig, d)

    by = {r["vehicle_alg"] + "/" + r["authority_alg"]: r for r in rows}
    mldsa = by["ML-DSA-44/ML-DSA-44"]
    falcon = by["Falcon-512/ML-DSA-44"]
    ok = (
        mldsa["msg_with_digest_bytes"] > FRAME_LIMIT
        and falcon["msg_with_digest_bytes"] <= FRAME_LIMIT
    )
    return write_outcome(d, Outcome(
        "E8", "Message size vs packet limit",
        "ML-DSA alone overflows a BSM; Falcon + certificate digest fits",
        f"ML-DSA-44 safety message: {mldsa['msg_with_digest_bytes']:,} B even with a digest "
        f"({mldsa['frames_with_digest']} frames); Falcon-512 + digest: "
        f"{falcon['msg_with_digest_bytes']:,} B, at most "
        f"{falcon['msg_with_digest_worst_bytes']:,} B with the longest possible signature "
        f"(fits 1,400 B). Messages carrying the full "
        f"certificate overflow for every post-quantum option "
        f"({falcon['msg_with_cert_bytes']:,} B with an ML-DSA authority).",
        ok, numbers={r["config"]: {"digest": r["msg_with_digest_bytes"],
                                   "cert": r["msg_with_cert_bytes"]} for r in rows},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
