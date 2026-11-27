"""Fill the "theory vs measured" tables in report/math/ from the recorded results.

    python scripts/build_math_tables.py           # rewrite the tables in place
    python scripts/build_math_tables.py --check   # exit 1 if any table is out of date

Each table sits between markers in a report/math/*.md file:

    <!-- BEGIN GENERATED: name -->
    ...
    <!-- END GENERATED: name -->

Predictions come from qsv2v.formulas (the derivations, as code); measurements
come from results/experiments/ and results/sim/crypto_profile.json, produced by
``python -m qsv2v.experiments``. No measured number is typed by hand.
tests/test_formulation.py runs the --check mode, so the report cannot drift
from the results.
"""

from __future__ import annotations

import csv
import json
import math
import re
import sys
from fractions import Fraction
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qsv2v import formulas as F  # noqa: E402
from qsv2v.sim.radio import RadioConfig  # noqa: E402

RES = ROOT / "results" / "experiments"
PROFILE = ROOT / "results" / "sim" / "crypto_profile.json"
MATH = ROOT / "report" / "math"
E1_PHOTONS, SAMPLE_FRACTION = 50_000, 0.1  # E1 settings (qsv2v/experiments/e01_eve_detection.py)


# -- helpers --------------------------------------------------------------------
def rows(name: str, file: str = "summary.csv") -> list[dict]:
    with open(RES / name / file, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def result(name: str) -> dict:
    return json.loads((RES / name / "result.json").read_text(encoding="utf-8"))


def num(x) -> float:
    return float(x)


def table(header: list[str], body: list[list]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in body]
    return "\n".join(out)


def pct(x: float, d: int = 2) -> str:
    return f"{100 * x:.{d}f}%"


def inside(theory: float, mean: float, ci: float) -> str:
    return "yes" if abs(theory - mean) <= ci + 1e-12 else "no"


# -- 01_qkd.md --------------------------------------------------------------------
def t_sift() -> str:
    from qsv2v.qkd.bb84 import run_bb84

    rng = np.random.default_rng(20261125)
    r = run_bb84(1_000_000, rng=rng)
    ratio = r.sift_ratio
    sigma = math.sqrt(0.25 / r.n_sent)
    return table(
        ["Quantity", "Theory", "Measured (NumPy backend, 10^6 photons, seed 20261125)"],
        [
            ["Sift ratio", "1/2", f"{ratio:.5f} ({(ratio - 0.5) / sigma:+.2f} σ, σ = {sigma:.5f})"],
            ["QBER, no noise and no Eve", "0", f"{r.qber:.4f} ({r.errors} errors in "
                                                f"{r.sifted_length:,} sifted bits)"],
        ],
    )  # fmt: skip


def t_qber() -> str:
    body = []
    for r in rows("e01_eve_detection"):
        e, f = num(r["noise"]), num(r["eve_fraction"])
        if round(f * 10, 6) % 2:  # every 0.2
            continue
        fe, ff = Fraction(str(e)), Fraction(str(f))
        q = F.qber_by_enumeration(fe, fe, ff)
        m, ci = num(r["qber_estimated"]), num(r["qber_estimated_ci95"])
        body.append([pct(e, 0), f"{f:.1f}", f"{float(q):.4f} (= {q})", f"{f / 4:.4f}",
                     f"{m:.4f} ± {ci:.4f}", inside(float(q), m, ci)])  # fmt: skip
    return table(
        ["Noise e", "Eve f", "Exact Q (enumeration)", "First-order e + f/4 at e = 0",
         "Measured (10 runs, ± 95% CI)", "Exact Q inside CI"],
        body,
    )  # fmt: skip


def t_abort() -> str:
    summ = rows("e01_eve_detection")
    m = round(SAMPLE_FRACTION * E1_PHOTONS / 2)
    head = []
    for e in (0.0, 0.02):
        pts = [r for r in summ if num(r["noise"]) == e]
        xs = [num(r["eve_fraction"]) for r in pts]
        ys = [num(r["abort_rate"]) for r in pts]
        f50 = float(np.interp(0.5, ys, xs))
        head.append([pct(e, 0), f"{F.abort_fraction(e):.4f}", f"{f50:.4f}"])
    detail = []
    for e, fs in ((0.0, (0.35, 0.40, 0.45, 0.50)), (0.02, (0.30, 0.35, 0.40, 0.45))):
        for r in summ:
            if num(r["noise"]) == e and any(abs(num(r["eve_fraction"]) - f) < 1e-9 for f in fs):
                f = num(r["eve_fraction"])
                q = F.qber_closed_form(e, f)
                detail.append([pct(e, 0), f"{f:.2f}", f"{q:.4f}",
                               f"{F.abort_probability(q, m):.2f}",
                               f"{num(r['abort_rate']):.1f} ({int(r['n'])} runs)"])  # fmt: skip
    return (
        table(["Noise e", "Predicted abort point f*", "Measured 50%-abort point"], head)
        + "\n\n"
        + table([
            "Noise e", "Eve f", "Expected Q", f"Predicted P(abort), m = {m:,}",
            "Measured abort rate"], detail)
    )  # fmt: skip


def _e02_point(e: float, data: list[dict], summ: dict) -> dict:
    """Prediction at one E2 noise level from its measured QBER and Cascade efficiency."""
    r = summ[e]
    q, f = num(r["qber_measured"]), num(r["cascade_f"])
    runs = [x for x in data if num(x["noise"]) == e]
    n_key = float(np.mean([num(x["sifted_bits"]) for x in runs]))
    mu = F.key_fraction(q, f) - F.finite_key_overhead(int(n_key))
    sigma = F.key_fraction_sampling_sigma(q, n_key / 9)  # 10% of sifted bits disclosed
    return {"q": q, "f": f, "n_key": n_key, "mu": mu, "sigma": sigma, "runs": len(runs),
            "clipped": F.clipped_mean(mu, sigma), "p_key": F.prob_positive(mu, sigma),
            "measured": num(r["key_fraction"]), "ci": num(r["key_fraction_ci95"]),
            "with_key": sum(num(x["final_key_bits"]) > 0 for x in runs)}  # fmt: skip


def t_keyfraction() -> str:
    data = rows("e02_channel_noise", "data.csv")
    summ = {num(r["noise"]): r for r in rows("e02_channel_noise")}
    body = []
    for e in (0.01, 0.03, 0.05, 0.07, 0.09):
        p = _e02_point(e, data, summ)
        s_mean = p["sigma"] / math.sqrt(p["runs"])
        body.append(
            [
                f"{p['q']:.4f}",
                f"{p['f']:.3f}",
                f"{F.key_fraction(p['q'], 1.0):.4f}",
                f"{p['mu']:.4f}",
                f"{p['measured']:.4f} ± {p['ci']:.4f}",
                f"{s_mean:.4f}",
                f"{(p['measured'] - p['mu']) / s_mean:+.1f}",
            ]
        )
    near = []
    for e in (0.09, 0.095, 0.1, 0.105):
        p = _e02_point(e, data, summ)
        near.append([f"{p['q']:.4f}", f"{p['mu']:+.4f}", f"{p['clipped']:.4f}",
                     f"{p['measured']:.4f}", f"{p['runs'] * p['p_key']:.1f}",
                     f"{p['with_key']}/{p['runs']}"])  # fmt: skip
    res = result("e02_channel_noise")["numbers"]
    fbar = res["cascade_f"]
    n_key = np.mean([num(x["sifted_bits"]) for x in data if 0.08 <= num(x["noise"]) <= 0.11])
    over = F.finite_key_overhead(int(n_key))
    lo, hi = 1e-6, 0.5
    for _ in range(200):  # zero of 1 - (1 + f) h(Q) - overhead
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if F.key_fraction(mid, fbar) - over > 0 else (lo, mid)
    grid = sorted(summ)
    last_key = max(num(summ[e]["qber_measured"]) for e in grid if num(summ[e]["key_fraction"]) > 0)
    zero = [
        ["Perfect code, f = 1 (Shor–Preskill)", pct(F.zero_key_qber(1.0)), "—"],
        [f"Cascade, measured mean f = {fbar:.3f}", pct(F.zero_key_qber(fbar)), "—"],
        [f"… plus the fixed 131-bit overhead (n ≈ {n_key:,.0f})", pct(lo),
         f"between {pct(last_key)} (last grid point with key) and "
         f"{pct(res['zero_key_qber'])} (first with none)"],
    ]  # fmt: skip
    return (
        table(["Measured QBER", "Measured Cascade f", "1 − 2h(Q)",
               "Predicted μ = 1 − (1+f)h(Q) − 131/n", "Measured key fraction (± 95% CI)",
               "σ of a 10-run mean (QBER sampling)", "(measured − μ) / σ"], body)
        + "\n\n"
        + table(["Measured QBER", "μ", "Predicted mean of max(0, ·)", "Measured mean",
                 "Predicted runs with a key", "Measured runs with a key"], near)
        + "\n\n"
        + table(["Zero-key point", "Predicted QBER", "Measured (E2)"], zero)
    )  # fmt: skip


def t_distance() -> str:
    link = F.LinkModel()
    summ = rows("e03_distance_loss")
    res = result("e03_distance_loss")["numbers"]
    body = []
    for r in summ:
        d = int(num(r["distance_km"]))
        if d % 50:
            continue
        body.append(
            [
                d,
                f"{link.eta(d):.3e}",
                f"{link.qber(d):.4f}",
                f"{num(r['qber']):.4f}",
                f"{link.key_rate(d):.3e}",
                f"{num(r['skr_asymptotic']):.3e} ± {num(r['skr_asymptotic_ci95']):.1e}",
            ]
        )
    pos = [int(num(r["distance_km"])) for r in summ if num(r["skr_asymptotic"]) > 0]
    zero = [int(num(r["distance_km"])) for r in summ if num(r["skr_asymptotic"]) <= 0]
    tail = [
        ["Loss slope of the key rate", f"{link.alpha_db_per_km:.2f} dB/km",
         f"{res['db_per_km']:.3f} dB/km (fit, 0–120 km)"],
        ["Distance where the key rate reaches zero", f"{link.cutoff_km():.1f} km",
         f"between {max(pos)} and {min(zero)} km (10 km grid)"],
    ]  # fmt: skip
    return (
        table(["km", "η(d)", "Q(d) theory", "Q measured", "R(d) theory (bits/pulse)",
               "R measured (± 95% CI)"], body)
        + "\n\n" + table(["Quantity", "Theory", "Measured (E3)"], tail)
    )  # fmt: skip


def t_cascade() -> str:
    """First Cascade pass: predicted vs counted odd-parity blocks (fresh runs, fixed seeds)."""
    from qsv2v.qkd.cascade import cascade, initial_block_size

    body = []
    n = 100_000
    for q in (0.01, 0.03, 0.05, 0.08):
        rng = np.random.default_rng(int(q * 1000))
        alice = rng.integers(0, 2, n, dtype=np.uint8)
        bob = alice ^ (rng.random(n) < q).astype(np.uint8)
        k = initial_block_size(q)
        res = cascade(alice, bob, q, rng)
        blocks = math.ceil(n / k)
        body.append(
            [
                f"{q:.2f}",
                k,
                blocks,
                f"{blocks * F.cascade_odd_block_prob(q, k):.0f}",
                res.parity_mismatches_per_pass[0],
                F.cascade_binary_leak(k),
            ]
        )
    return table(
        [
            "Q",
            "k1 = ⌈0.73/Q⌉",
            "Blocks",
            "Predicted odd blocks",
            "Counted odd blocks (n = 10^5)",
            "Parities per BINARY search",
        ],
        body,
    )


# -- 02_attacks.md --------------------------------------------------------------------
def t_attacks() -> str:
    body = []
    for r in rows("e05_attack_success"):
        body.append(
            [r["paper"], r["attack"], f"{r['successes']}/{r['runs']}", f"{num(r['seconds']):.3g} s"]
        )
    return table(["Target", "Attack", "Succeeded", "Mean time per run"], body)


# -- 04_network.md ----------------------------------------------------------------------
def t_sizes() -> str:
    prof = json.loads(PROFILE.read_text(encoding="utf-8"))
    hs = prof["handshakes"]
    e8 = {r["config"]: r for r in rows("e08_message_size")}
    kem = F.mlkem_sizes(3, 10, 4)
    dsa = F.mldsa_sizes(4, 4, 8380417, 13, 2**17, 80, 128)
    lib = {}
    try:
        import oqs

        with oqs.KeyEncapsulation("ML-KEM-768") as k:
            lib.update(ek=k.details["length_public_key"], dk=k.details["length_secret_key"],
                       ct=k.details["length_ciphertext"])  # fmt: skip
        with oqs.Signature("ML-DSA-44") as s:
            lib.update(dpk=s.details["length_public_key"], dsig=s.details["length_signature"])
        with oqs.Signature("Falcon-512") as s:
            lib.update(fpk=s.details["length_public_key"], fsig=s.details["length_signature"])
    except Exception:  # liboqs not installed: fall back to the measured E6/E8 sizes
        pass
    cert_d = F.cert_size("ML-DSA-44", dsa["pk"], dsa["sig"])
    cert_e = F.cert_size("ECDSA-P256", 64, 64)
    pq = F.handshake_sizes(kem["ek"], kem["ct"], cert_d, dsa["sig"])
    hy = F.handshake_sizes(kem["ek"], kem["ct"], cert_d, dsa["sig"], x_pub=32)
    cl = F.handshake_sizes(32, 32, cert_e, 64)
    mldsa_row = e8["ML-DSA-44, ML-DSA-44 authority"]
    ecdsa_row = e8["ECDSA P-256 (today, IEEE 1609.2)"]
    falcon_row = e8["Falcon-512, Falcon-512 authority"]
    L = lambda k: lib.get(k, "—")  # noqa: E731
    body = [
        ["ML-KEM-768 encapsulation key", "384k + 32", kem["ek"], L("ek")],
        ["ML-KEM-768 decapsulation key", "768k + 96", kem["dk"], L("dk")],
        ["ML-KEM-768 ciphertext", "32(d_u k + d_v)", kem["ct"], L("ct")],
        ["ML-DSA-44 public key", "32 + 32k(bitlen(q−1) − d)", dsa["pk"], L("dpk")],
        ["ML-DSA-44 signature", "λ/4 + 32ℓ(1 + bitlen(γ₁−1)) + ω + k", dsa["sig"], L("dsig")],
        ["Falcon-512 public key", "1 + 14n/8", F.falcon_pk_size(512), L("fpk")],
        ["Pseudonym certificate, ML-DSA-44 / ML-DSA-44 CA", "83 + len(alg) + pk + σ_CA", cert_d,
         mldsa_row["cert_bytes"]],
        ["Pseudonym certificate, ECDSA / ECDSA CA", "83 + len(alg) + pk + σ_CA", cert_e,
         ecdsa_row["cert_bytes"]],
        ["Handshake m1 (ML-KEM-768 + ML-DSA-44)", "62 + ek + x + cert + σ", pq["m1"],
         hs["pq-mldsa"]["m1_bytes"]],
        ["Handshake m2 (ML-KEM-768 + ML-DSA-44)", "98 + ct + x + cert + σ", pq["m2"],
         hs["pq-mldsa"]["m2_bytes"]],
        ["Handshake m3", "2 + lp(32)", pq["m3"], hs["pq-mldsa"]["m3_bytes"]],
        ["Handshake m1 / m2, hybrid (+ X25519)", "x = 32", f"{hy['m1']} / {hy['m2']}",
         f"{hs['hybrid-mldsa']['m1_bytes']} / {hs['hybrid-mldsa']['m2_bytes']}"],
        ["Handshake m1 / m2, classical (X25519 + ECDSA)", "ek = ct = 32, σ = 64",
         f"{cl['m1']} / {cl['m2']}",
         f"{hs['classical']['m1_bytes']} / {hs['classical']['m2_bytes']}"],
        ["Safety message + digest, ML-DSA-44", "36 + len(alg) + payload + σ",
         F.bsm_size("ML-DSA-44", 200, dsa["sig"]), mldsa_row["msg_with_digest_bytes"]],
        ["Safety message + certificate, ML-DSA-44", "… + (cert − 8)",
         F.bsm_size("ML-DSA-44", 200, dsa["sig"], cert_d), mldsa_row["msg_with_cert_bytes"]],
        ["Safety message + digest, ECDSA", "36 + len(alg) + payload + σ",
         F.bsm_size("ECDSA-P256", 200, 64), ecdsa_row["msg_with_digest_bytes"]],
        ["Safety message + digest, Falcon-512, longest signature",
         f"σ = {L('fsig')} (liboqs maximum)",
         F.bsm_size("Falcon-512", 200, lib.get("fsig", int(falcon_row["sig_max_bytes"]))),
         falcon_row["msg_with_digest_worst_bytes"]],
    ]  # fmt: skip
    for r in body:
        r.append("yes" if str(r[2]) == str(r[3]) else "**no**")
    return table(["Object (bytes)", "Formula", "Formula gives", "Measured", "Equal"], body)


def t_latency() -> str:
    prof = json.loads(PROFILE.read_text(encoding="utf-8"))["handshakes"]
    e9 = rows("e09_network_scale")
    body = []
    for name in ("classical", "pq-falcon", "pq-mldsa"):
        h = prof[name]
        sizes = (h["m1_bytes"], h["m2_bytes"], h["m3_bytes"])
        comp = (h["t_initiate"], h["t_respond"], h["t_finish"], h["t_confirm"])
        l0 = F.handshake_latency_zero_load(sizes, comp)
        frames = sum(len(RadioConfig().fragments(s)) for s in sizes)
        m = next(
            r
            for r in e9
            if r["sweep"] == "handshake"
            and r["hs_policy"] == "all"
            and r["handshake_profile"] == name
            and int(r["n_vehicles"]) == 10
            and r["bsm_profile"] == "falcon"
            and num(r["speed_scale"]) == 1.0
        )
        p50, ci = num(m["hs_latency_ms_p50"]), num(m["hs_latency_ms_p50_ci95"])
        body.append([name, frames, f"{1e3 * sum(comp):.2f}", f"{1e3 * l0:.2f}",
                     f"{p50:.1f} ± {ci:.1f}", f"{p50 / (1e3 * l0):.2f}"])  # fmt: skip
    return table(
        [
            "Handshake",
            "Frames",
            "Compute (ms)",
            "Predicted L0, idle channel (ms)",
            "Measured median, 10 vehicles (ms, ± 95% CI)",
            "Measured / L0",
        ],
        body,
    )


def t_cbr() -> str:
    prof = json.loads(PROFILE.read_text(encoding="utf-8"))["broadcasts"]
    e9 = rows("e09_network_scale")
    body = []
    for name in ("ecdsa", "falcon", "mldsa"):
        b = prof[name]
        for r in e9:
            if r["sweep"] == "broadcast" and r["bsm_profile"] == name:
                n = int(r["n_vehicles"])
                rho = F.offered_load(n, b["msg_digest_bytes"], b["msg_cert_bytes"])
                m, ci = num(r["cbr_mean"]), num(r["cbr_mean_ci95"])
                body.append(
                    [
                        name,
                        n,
                        f"{rho:.3f}",
                        f"{m:.3f} ± {ci:.3f}",
                        inside(rho, m, ci) if rho < 0.5 else "saturating",
                    ]
                )
    return table(
        ["Signature", "Vehicles", "Predicted busy ratio ρ", "Measured (± 95% CI)", "ρ inside CI"],
        body,
    )


def t_e10() -> str:
    e10 = result("e10_qkd_vs_pqc")["numbers"]
    link = F.LinkModel()
    t_hs = e10["pqc_handshake_ms"] / 1e3
    return table(
        ["Quantity", "Formula", "Formula gives", "E10 reports"],
        [["PQC key rate per core", "256 bit / t_handshake", f"{256 / t_hs:,.0f} bit/s",
          f"{e10['pqc_bps']:,.0f} bit/s"],
         ["QKD key rate at 0 km", "R(0) × 10^8 pulses/s", f"{link.key_rate(0) * 1e8:,.0f} bit/s",
          f"{e10['qkd_bps_0km']:,.0f} bit/s"],
         ["QKD key rate at 50 km", "R(50) × 10^8 pulses/s",
          f"{link.key_rate(50) * 1e8:,.0f} bit/s", f"{e10['qkd_bps_50km']:,.0f} bit/s"]],
    )  # fmt: skip


# -- 05_security_parameters.md ---------------------------------------------------------------
def t_generic_costs() -> str:
    return table(
        ["Attack", "Formula", "log2 cost"],
        [["Pollard rho on P-256 (classical)", "√(π n / 4), n = group order",
          f"{F.pollard_rho_bits(F.P256_ORDER):.1f}"],
         ["Grover on a 128-bit key (quantum iterations)", "(π/4) 2^(k/2)",
          f"{F.grover_bits(128):.1f}"],
         ["Grover on a 256-bit key (quantum iterations)", "(π/4) 2^(k/2)",
          f"{F.grover_bits(256):.1f}"],
         ["Birthday collision on SHA-256 (classical)", "√(π 2^n / 2)",
          f"{F.birthday_bits(256):.1f}"],
         ["Shor on P-256: logical qubits", "9n + 2⌈log2 n⌉ + 10, n = 256",
          f"{F.roetteler_qubits(256)} qubits (not a log)"]],
    )  # fmt: skip


TABLES = {
    "01_qkd.md": {
        "sift": t_sift,
        "qber": t_qber,
        "abort": t_abort,
        "cascade": t_cascade,
        "keyfraction": t_keyfraction,
        "distance": t_distance,
    },
    "02_attacks.md": {"attacks": t_attacks},
    "04_network.md": {"sizes": t_sizes, "latency": t_latency, "cbr": t_cbr, "e10": t_e10},
    "05_security_parameters.md": {"generic_costs": t_generic_costs},
}


def render(text: str, tables: dict) -> str:
    for name, fn in tables.items():
        pat = re.compile(
            rf"(<!-- BEGIN GENERATED: {name} -->\n).*?(<!-- END GENERATED: {name} -->)", re.S
        )
        if not pat.search(text):
            raise SystemExit(f"marker for table '{name}' not found")
        body = fn()
        text = pat.sub(lambda m, b=body: m.group(1) + b + "\n" + m.group(2), text)
    return text


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for fname, tables in TABLES.items():
        path = MATH / fname
        old = path.read_text(encoding="utf-8")
        new = render(old, tables)
        if new != old:
            stale.append(fname)
            if not check:
                path.write_text(new, encoding="utf-8")
    if check and stale:
        print("out of date:", ", ".join(stale))
        return 1
    print("checked" if check else "written", "-", ", ".join(TABLES))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
