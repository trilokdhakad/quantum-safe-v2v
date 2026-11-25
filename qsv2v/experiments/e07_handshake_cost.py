"""E7 -- Handshake cost: compute, bytes on air and round trips for every protocol.

PSLAP [Shariq et al., Computer Networks 261:111155, 2025], PSRS-D2D [Shariq et al.,
IEEE TMC 25(1):1445-1456, 2026] and P²AS-IoAV [Shariq et al., IEEE TVT 75(10):
24698-24711, 2026], as implemented from the papers in Phase 4 (P²AS-IoAV with
the paper's Kyber-512 and with the ML-KEM-768 our attacks use), and
PQ-V2V-AKE in four configurations. Compute is the wall time of one complete
handshake (both parties, all checks), timed over many handshakes.

Fairness note: the papers' elliptic-curve steps run on the pure-Python ``ecdsa``
package, which is far slower than a C library. So the script also counts every
P-256 scalar multiplication in those handshakes and reports an "EC at C speed"
estimate: scalar multiplications x the time of one P-256 ECDH in ``cryptography``
(OpenSSL). PQ-V2V-AKE and P²AS-IoAV use liboqs (C) when available.

Wire sizes: byte fields at their length, EC points 64 B (uncompressed x||y, as
the papers hash them), timestamps 4 B (32-bit, as printed), other integers 32 B.
PQ-V2V-AKE messages are measured from their real encoding.
"""

from __future__ import annotations

import dataclasses
import time
from contextlib import contextmanager
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

NAME = "e07_handshake_cost"

# Security properties, as established by the Phase 4 attacks and Phase 5 tests/Scyther.
FEATURES = {
    "PSLAP": dict(forward_secrecy="yes", quantum_resistant="no", revocation="no",
                  unlinkable="no (static PID on air)", capture_resistant="partial",
                  offline_guessing_resistant="no"),
    "PSRS-D2D": dict(forward_secrecy="no", quantum_resistant="no", revocation="no",
                     unlinkable="no", capture_resistant="no (2 certs give master key)",
                     offline_guessing_resistant="n/a"),
    "P²AS-IoAV": dict(forward_secrecy="no (static keys only)", quantum_resistant="yes (ML-KEM)",
                      revocation="no", unlinkable="partial", capture_resistant="no (TA key escrow)",
                      offline_guessing_resistant="n/a"),
    "PQ-V2V-AKE": dict(forward_secrecy="yes", quantum_resistant="yes", revocation="yes (CRL)",
                       unlinkable="yes (rotating pseudonyms)", capture_resistant="yes",
                       offline_guessing_resistant="yes (no password)"),
    # The same protocol with X25519 + ECDSA: ephemeral keys and the CRL remain, quantum
    # safety does not.
    "Classical baseline": dict(forward_secrecy="yes", quantum_resistant="no",
                               revocation="yes (CRL)", unlinkable="yes (rotating pseudonyms)",
                               capture_resistant="yes",
                               offline_guessing_resistant="yes (no password)"),
}  # fmt: skip


def wire_size(msg) -> int:
    if hasattr(msg, "encode"):
        return len(msg.encode())
    n = 0
    for f in dataclasses.fields(msg):
        v = getattr(msg, f.name)
        if isinstance(v, bytes):
            n += len(v)
        elif isinstance(v, int):
            n += 4 if f.name.upper().startswith("T") else 32  # 32-bit timestamps, as printed
        else:
            n += 64  # elliptic-curve point
    return n


@contextmanager
def count_scalar_mults():
    """Count P-256 scalar multiplications done through ``ecdsa``'s PointJacobi."""
    from ecdsa.ellipticcurve import PointJacobi

    box = {"n": 0, "depth": 0}
    orig = {k: getattr(PointJacobi, k) for k in ("__mul__", "__rmul__", "mul_add")}

    def wrap(fn, weight):
        def w(self, *a, **kw):
            if box["depth"] == 0:
                box["n"] += weight
            box["depth"] += 1
            try:
                return fn(self, *a, **kw)
            finally:
                box["depth"] -= 1

        return w

    PointJacobi.__mul__ = wrap(orig["__mul__"], 1)
    PointJacobi.__rmul__ = wrap(orig["__rmul__"], 1)
    PointJacobi.mul_add = wrap(orig["mul_add"], 2)
    try:
        yield box
    finally:
        for k, v in orig.items():
            setattr(PointJacobi, k, v)


def ecdh_ms(reps: int = 300) -> float:
    from cryptography.hazmat.primitives.asymmetric import ec

    from qsv2v.pqc.bench import median_ms

    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    pub = b.public_key()
    return median_ms(lambda: a.exchange(ec.ECDH(), pub), reps)


def protocols(seed: int):
    """(name, variant, implementation, make_handshake) -- each returns (messages, run)."""
    from qsv2v.attacks.common import SimClock
    from qsv2v.crypto.rng import DeterministicRNG
    from qsv2v.pqc.sig import oqs_available

    oqs = oqs_available()
    out = []

    def psrs():
        from qsv2v.attacks.psrs_d2d import protocol as P

        rng = DeterministicRNG(seed)
        net, clock = P.build_network(2, rng), SimClock()
        di, dj = net.drones
        return lambda: P.handshake(di, dj, net.directory, clock, rng)

    def pslap():
        from qsv2v.attacks.pslap import attacks as A
        from qsv2v.attacks.pslap import protocol as P

        rng, clock, ta, drones, vehicles = A.make_fleet(seed, 1, 1, [b"correct horse"])
        return lambda: P.handshake(vehicles[0], drones[0], ta, clock, rng, "text")

    def p2as(kem_alg):
        def make():
            from qsv2v.attacks.p2as_ioav import attacks as A
            from qsv2v.attacks.p2as_ioav import protocol as P

            rng, kem, ta, avs, drs = A.make_network(
                seed, 1, 1, "oqs" if oqs else "kyber-py", kem_alg=kem_alg
            )
            clock = SimClock()
            return lambda: P.handshake(kem, avs[0], drs[0], ta, clock, rng, b"x" * 32)

        return make

    def ours(**kw):
        def make():
            from qsv2v.pqc import pq_v2v_ake as A

            be = dict(kem_backend="oqs", sig_backend="oqs") if oqs else {}
            net = A.setup_network(2, seed, **be, **kw)
            return lambda: A.handshake(*net.vehicles, net.clock)

        return make

    ec_impl = "pure-Python ecdsa (P-256)"
    out += [
        ("PSLAP", "as printed (§4.3)", ec_impl, pslap),
        ("PSRS-D2D", "as printed", ec_impl, psrs),
        ("P²AS-IoAV", "Kyber-512 (as the paper evaluates)",
         "ML-KEM-512 " + ("liboqs" if oqs else "kyber-py"), p2as("ML-KEM-512")),
        ("P²AS-IoAV", "ML-KEM-768 (as in our attacks)",
         "ML-KEM-768 " + ("liboqs" if oqs else "kyber-py"), p2as("ML-KEM-768")),
        ("PQ-V2V-AKE", "ML-KEM-768 + ML-DSA-44", "liboqs" if oqs else "pure Python",
         ours()),
        ("PQ-V2V-AKE", "hybrid: + X25519", "liboqs + cryptography" if oqs else "pure Python",
         ours(hybrid=True)),
    ]  # fmt: skip
    if oqs:
        out.append(("PQ-V2V-AKE", "ML-KEM-768 + Falcon-512", "liboqs",
                    ours(sig_alg="Falcon-512")))  # fmt: skip
    out.append(("Classical baseline", "same protocol, X25519 + ECDSA P-256", "cryptography",
                ours(sig_alg="ECDSA-P256", kem_alg="X25519")))  # fmt: skip
    return out


def messages_of(session) -> list:
    if hasattr(session, "m3"):  # PQ-V2V-AKE transcript
        return [session.m1, session.m2, session.m3]
    if hasattr(session, "msg1"):
        return [session.msg1, session.msg2]
    return [session.m1, session.m2]


def run(base: Path | None = None, quick: bool = False, log=print) -> Outcome:
    d = outdir(base, NAME)
    reps = 3 if quick else 40
    c_ms = ecdh_ms(50 if quick else 400)
    rows = []
    for name, variant, impl, make in protocols(seed=7):
        hs = make()
        sess = hs()  # warm-up; also gives the messages
        msgs = messages_of(sess)
        sizes = [wire_size(m) for m in msgs]
        with count_scalar_mults() as box:
            hs()
        mults = box["n"]
        for k in range(reps):
            t0 = time.perf_counter()
            hs()
            rows.append({
                "protocol": name, "variant": variant, "implementation": impl, "rep": k,
                "compute_ms": 1000 * (time.perf_counter() - t0), "messages": len(msgs),
                "round_trips": len(msgs) / 2, "bytes_total": sum(sizes),
                "bytes_per_message": " / ".join(map(str, sizes)),
                "ec_scalar_mults": mults,
                "ec_at_c_speed_ms": mults * c_ms if mults else None,
            })  # fmt: skip
        log(f"  E7: {name} ({variant}) done")
    write_csv(d / "data.csv", rows)
    summ = aggregate(rows, ["protocol", "variant", "implementation", "messages", "round_trips",
                            "bytes_total", "bytes_per_message", "ec_scalar_mults"],
                     ["compute_ms", "ec_at_c_speed_ms"])  # fmt: skip
    for r in summ:
        r.update(FEATURES.get(r["protocol"], {k: "—" for k in FEATURES["PSLAP"]}))
        r["ecdh_ms_openssl"] = c_ms
    write_csv(d / "summary.csv", summ)
    write_table(d / "table.md", summ, [
        ("protocol", "Protocol"), ("variant", "Variant"), ("implementation", "Implementation"),
        ("compute_ms±", "Compute (ms)"), ("ec_scalar_mults", "EC scalar mults"),
        ("ec_at_c_speed_ms", "EC at C speed (ms)"), ("bytes_per_message", "Bytes per message"),
        ("bytes_total", "Bytes on air"), ("messages", "Messages"),
        ("forward_secrecy", "Forward secrecy"), ("quantum_resistant", "Quantum resistant"),
        ("revocation", "Revocation"), ("unlinkable", "Unlinkable"),
        ("capture_resistant", "Capture resistant"),
    ], digits=3)  # fmt: skip

    fig, (a1, a2) = figure(10.0, 3.8, ncols=2)
    labels = [f"{r['protocol']}\n{r['variant']}" for r in summ][::-1]
    comp = [r["compute_ms"] for r in summ][::-1]
    cspeed = [r["ec_at_c_speed_ms"] for r in summ][::-1]
    a1.barh(labels, comp, color=COLORS[0], height=0.6, label="Measured (this implementation)")
    ys = [i for i, v in enumerate(cspeed) if v == v and v is not None]
    a1.plot([cspeed[i] for i in ys], ys, "D", color=COLORS[1], ms=5,
            label="Papers' EC steps at OpenSSL speed (estimate)")  # fmt: skip
    a1.set_xscale("log")
    from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

    a1.xaxis.set_major_locator(LogLocator(base=10))
    a1.xaxis.set_minor_formatter(NullFormatter())
    a1.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    a1.set_xlabel("Compute per handshake, both parties (ms, log)")
    a1.set_title("Compute cost")
    a1.legend(fontsize=7.5, loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=2)
    a2.barh(labels, [r["bytes_total"] for r in summ][::-1], color=COLORS[2], height=0.6)
    for y, r in enumerate(summ[::-1]):
        a2.text(r["bytes_total"] * 1.03, y, f"{r['bytes_total']:,} B, {r['messages']} msgs",
                va="center", fontsize=7.5)  # fmt: skip
    a2.set_xlim(right=max(r["bytes_total"] for r in summ) * 1.45)
    a2.set_xlabel("Bytes on air per handshake")
    a2.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:g} k" if v else "0"))
    a2.set_title("Communication cost")
    a2.set_yticklabels([])
    for ax in (a1, a2):
        ax.tick_params(axis="y", labelsize=7.5)
        ax.grid(axis="y", visible=False)
    save(fig, d)

    ours = next(r for r in summ if r["protocol"] == "PQ-V2V-AKE")
    papers = [r for r in summ if r["protocol"] in ("PSLAP", "PSRS-D2D", "P²AS-IoAV")
              and "768" not in r["variant"]]  # fmt: skip
    more_bytes = all(ours["bytes_total"] > r["bytes_total"] for r in papers)
    return write_outcome(d, Outcome(
        "E7", "Handshake cost",
        "Ours costs more bytes, adds forward secrecy and revocation",
        f"PQ-V2V-AKE (ML-DSA) uses {ours['bytes_total']:,} B in 3 messages vs "
        + ", ".join(f"{r['protocol']} {r['bytes_total']:,} B" for r in papers)
        + f" in 2; compute {ours['compute_ms']:.1f} ms vs "
        + ", ".join(f"{r['protocol']} {r['compute_ms']:.1f} ms" for r in papers)
        + " (EC papers at OpenSSL speed: "
        + ", ".join(f"{r['protocol']} ≈ {r['ec_at_c_speed_ms']:.2f} ms" for r in papers
                    if r["ec_at_c_speed_ms"] == r["ec_at_c_speed_ms"]
                    and r["ec_at_c_speed_ms"] is not None)
        + "). It is the only one with forward secrecy, revocation and quantum resistance together.",
        more_bytes,
        numbers={r["protocol"] + " / " + r["variant"]: {"compute_ms": r["compute_ms"],
                 "bytes": r["bytes_total"], "messages": r["messages"]} for r in summ},
    ))  # fmt: skip


if __name__ == "__main__":
    print(run().finding)
