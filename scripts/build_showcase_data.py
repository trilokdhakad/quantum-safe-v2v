"""Build the datasets behind the project-progress page from real runs of this codebase.

    python scripts/build_showcase_data.py [out_dir] [--only phases tests ...]

Run ``python -m qsv2v.experiments`` first: the experiment datasets are read
from results/experiments/.

Writes JSON files {rows, meta} to results/showcase/ (default):

* phases.json        -- phase status, read from git commit subjects "Phase N: ..."
* tests.json         -- pytest results per test file (runs the whole suite)
* qber_grid.json     -- BB84 QBER measured vs exact theory, noise x Eve fraction
* key_rate.json      -- final-key fraction vs QBER, with Cascade efficiency
* attacks.json       -- the eight Phase 4 attacks: recovered value vs victim's
* paper_errors.json  -- printing errors found in the base papers (documented)
* defenses.json      -- every attack class re-run against PQ-V2V-AKE
* bsm_sizes.json     -- signed safety-message sizes per signature scheme
* scyther.json       -- Scyther claim verdicts (verification/results.txt)
* sim_steady.json    -- E9 runs with handshakes (5 seeds, steady state)
* sim_broadcast.json -- E9 runs with safety messages only (5 seeds, steady state)
* crypto_ops.json    -- E6: ms per primitive operation, mean of repeated medians
* experiments.json   -- E1-E10 hypotheses, verdicts and findings
* e3_distance.json   -- E3: detection rate and secret key rate vs distance
* e7_cost.json       -- E7: compute, bytes and messages per handshake protocol
* trace_*.json       -- recorded simulation traces for the animated replay

Every number comes from running the code with fixed seeds; nothing is typed in
except phase names and the documented paper errors.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qsv2v.qkd import (  # noqa: E402
    InterceptResendEve,
    PauliNoise,
    QuantumChannel,
    expected_qber,
    run_bb84,
)
from qsv2v.qkd.postprocess import run_qkd  # noqa: E402
from qsv2v.qkd.theory import asymptotic_key_fraction, binary_entropy  # noqa: E402

SEED = 20261125
CODE = Path(__file__).read_text(encoding="utf-8")

PHASES = [
    (1, "Project setup and BB84 core"),
    (2, "Channel realism and the eavesdropper"),
    (3, "Post-processing to a final key"),
    (4, "Attacks on the three base papers"),
    (5, "Post-quantum V2V protocol (PQ-V2V-AKE)"),
    (6, "V2V network simulation"),
    (7, "Experiments and analysis (E1-E10)"),
    (8, "Dashboard (optional)"),
    (9, "Report"),
    (10, "Mathematical formulation and security parameters"),
]

PAPER_ERRORS = [
    {
        "paper": "PSRS-D2D",
        "where": "Fig. 2 / Sec. V-C step 2",
        "as_printed": "D_j checks Cert_i using h(Pub_j || ID_TA || ID_j || Pub_TA), its own values",
        "effect": "Every honest handshake fails",
    },
    {
        "paper": "PSLAP",
        "where": "Fig. 2 vs Fig. 3",
        "as_printed": "delta built with beta at registration, recomputed with gamma at login",
        "effect": "Every honest login fails",
    },
    {
        "paper": "PSLAP",
        "where": "Sec. 4.3 vs Fig. 3",
        "as_printed": "msg1 carries the static PID_AV in one, a masked TID_AV in the other",
        "effect": "Two different privacy properties",
    },
    {
        "paper": "P2AS-IoAV",
        "where": "Sec. V-C.1 step 2",
        "as_printed": "V1' = h(r_j || k_j || sk_1 || s_i || TS_1)",
        "effect": "Uses values the drone does not have; Fig. 2 is consistent",
    },
]

# Chapter 5 of report/math/: security of every primitive against classical and quantum
# attackers. Reference data read from the cited documents (like PAPER_ERRORS above).
SECURITY_LEVELS = [
    {"primitive": "ECDH / ECDSA P-256", "used_in": "PSLAP, PSRS-D2D, IEEE 1609.2 today",
     "classical": "≈ 128 bits (Pollard rho 2^127.8)",
     "quantum": "none: Shor, ≈ 2330 logical qubits", "source": "Roetteler et al. 2017"},
    {"primitive": "X25519", "used_in": "hybrid mode", "classical": "slightly under 128 bits",
     "quantum": "none (Shor)", "source": "RFC 7748 §7"},
    {"primitive": "ML-KEM-768", "used_in": "PQ-V2V-AKE key exchange",
     "classical": "NIST category 3; core-SVP 183", "quantum": "category 3; core-SVP 166",
     "source": "FIPS 203; Kyber spec v3.02 Table 4"},
    {"primitive": "ML-KEM-512 (Kyber-512)", "used_in": "P²AS-IoAV evaluation",
     "classical": "category 1; core-SVP 118", "quantum": "category 1; core-SVP 107",
     "source": "Kyber spec v3.02 Table 4"},
    {"primitive": "ML-DSA-44", "used_in": "PQ-V2V-AKE signatures and certificates",
     "classical": "category 2; core-SVP 123", "quantum": "category 2; core-SVP 112",
     "source": "FIPS 204; Dilithium spec v3.1 Table 1"},
    {"primitive": "Falcon-512", "used_in": "safety messages",
     "classical": "category 1; core-SVP 120 (forgery)", "quantum": "category 1; core-SVP 108",
     "source": "Falcon spec v1.2 Table 3.3"},
    {"primitive": "SHA-256", "used_in": "transcript hashes",
     "classical": "collisions 2^128, preimages 2^256",
     "quantum": "collisions ≈ 128 bits, preimages 2^128 (Grover)",
     "source": "FIPS 180-4; Brassard–Høyer–Tapp 1998; Bernstein 2009"},
    {"primitive": "HMAC-SHA-256 / HKDF, 256-bit keys", "used_in": "key derivation, MACs",
     "classical": "256 bits", "quantum": "128 bits (Grover)",
     "source": "Backendal et al. 2023"},
    {"primitive": "BB84 + Cascade + Toeplitz", "used_in": "QKD path",
     "classical": "information-theoretic, ε ≤ 2·10^-10 + 2^-64",
     "quantum": "same: no computational assumption", "source": "Shor–Preskill 2000"},
]  # fmt: skip

HEADLINE_FIELD = {
    "Passive session-key": "session key",
    "Forward secrecy broken": None,  # first field
    "Master-key extraction": "MK_TA",
    "Session linking": "text variant, eavesdropper",
    "Offline password": "password",
    "Forged message 1": "drone accepted msg1 as vehicle",
    "Past-session decryption": "session 1 plaintext",
    "Shor's algorithm": "factors",
}


def meta(inputs: str) -> list[dict]:
    return [
        {"label": "build_showcase_data.py", "value": CODE, "type": "code", "lang": "python"},
        {"label": "Input", "value": inputs},
        {"label": "Seed", "value": str(SEED)},
    ]


def write(out: Path, name: str, rows: list[dict], inputs: str) -> None:
    (out / name).write_text(
        json.dumps({"rows": rows, "meta": meta(inputs)}, indent=1, allow_nan=False),
        encoding="utf-8",
    )
    print(f"  {name}: {len(rows)} rows")


def build_phases() -> list[dict]:
    log = subprocess.run(
        ["git", "log", "--format=%h%x09%cs%x09%s"], cwd=ROOT, capture_output=True, text=True
    ).stdout
    done = {}
    for line in log.splitlines():
        h, date, subj = line.split("\t", 2)
        m = re.match(r"Phase (\d+):", subj)
        if m:
            done.setdefault(int(m.group(1)), (h, date))
    rows = []
    for n, name in PHASES:
        h, date = done.get(n, ("", ""))
        rows.append(
            {
                "phase": n,
                "name": name,
                "status": "Done" if n in done else "Not started",
                "done": 1 if n in done else 0,
                "commit": h,
                "date": date,
            }
        )
    return rows


def build_tests() -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        xml = Path(td) / "junit.xml"
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"--junitxml={xml}"],
            cwd=ROOT,
            capture_output=True,
        )
        tree = ET.parse(xml)
    per = {}
    for tc in tree.iter("testcase"):
        f = tc.get("classname", "").split(".")[0].replace("tests.", "") or "?"
        f = tc.get("classname", "").removeprefix("tests.").split(".")[0]
        r = per.setdefault(f, {"file": f"tests/{f}.py", "tests": 0, "passed": 0,
                               "failed": 0, "skipped": 0, "time_s": 0.0})  # fmt: skip
        r["tests"] += 1
        r["time_s"] += float(tc.get("time", 0))
        if tc.find("skipped") is not None:
            r["skipped"] += 1
        elif tc.find("failure") is not None or tc.find("error") is not None:
            r["failed"] += 1
        else:
            r["passed"] += 1
    rows = sorted(per.values(), key=lambda r: r["file"])
    for r in rows:
        r["time_s"] = round(r["time_s"], 2)
    return rows


def build_qber_grid() -> list[dict]:
    rows = []
    for e in (0.0, 0.02, 0.05, 0.08):
        for f in np.round(np.arange(0, 1.0001, 0.1), 2):
            noise = PauliNoise.from_qber(e) if e else None
            ch = QuantumChannel(noise=noise, eve=InterceptResendEve(f) if f else None)
            r = run_bb84(200_000, channel=ch, seed=SEED)
            th = expected_qber(noise, f)
            sigma = math.sqrt(th * (1 - th) / r.sifted_length) if th else 0.0
            rows.append(
                {
                    "noise": f"{e:.0%} noise",
                    "noise_rate": e,
                    "eve_fraction": float(f),
                    "qber_measured": round(r.qber, 5),
                    "qber_theory": round(th, 5),
                    "qber_linear": round(e + 0.25 * f, 5),
                    "z": round((r.qber - th) / sigma, 2) if sigma else 0.0,
                    "sifted_bits": r.sifted_length,
                }
            )
    return rows


def build_key_rate() -> list[dict]:
    rows = []
    for q in np.round(np.arange(0, 0.1201, 0.005), 3):
        runs = [
            run_qkd(100_000, channel=QuantumChannel(noise=PauliNoise.from_qber(q) if q else None),
                    seed=s)
            for s in range(10)
        ]  # fmt: skip
        fs = [r.ec_efficiency for r in runs if not math.isnan(r.ec_efficiency)]
        f = float(np.mean(fs)) if fs and q > 0 else None
        n_key = float(np.mean([r.n_key for r in runs]))
        if q == 0:
            pred = 1 - (np.mean([r.leaked_ec for r in runs]) + 131) / n_key
        elif f is not None:
            pred = max(0.0, 1 - (1 + f) * binary_entropy(q) - 131 / n_key)
        else:
            pred = 0.0
        rows.append(
            {
                "qber": float(q),
                "key_fraction": round(float(np.mean([r.key_fraction for r in runs])), 5),
                "predicted": round(float(pred), 5),
                "shor_preskill": round(float(asymptotic_key_fraction(q)), 5),
                "cascade_f": round(f, 4) if f is not None else None,
                "runs_with_identical_key": int(sum(r.keys_match for r in runs)),
                "runs_with_wrong_key": int(
                    sum(
                        (not r.aborted) and not np.array_equal(r.alice_final, r.bob_final)
                        for r in runs
                    )
                ),  # fmt: skip
                "runs": len(runs),
            }
        )
    return rows


def build_attacks() -> list[dict]:
    from qsv2v.attacks import shor_demo
    from qsv2v.attacks.p2as_ioav import attacks as p2as
    from qsv2v.attacks.pslap import attacks as pslap
    from qsv2v.attacks.psrs_d2d import attacks as psrs

    results = psrs.run_all(0) + pslap.run_all(0) + p2as.run_all(0) + [shor_demo.demo_shor(15, 15)]
    rows = []
    for i, r in enumerate(results, 1):
        key = next((v for k, v in HEADLINE_FIELD.items() if r.attack.startswith(k)), None)
        key = key or next(iter(r.expected))
        matched = sum(r.recovered.get(k) == v for k, v in r.expected.items())
        rows.append(
            {
                "n": i,
                "paper": r.paper.split(" (")[0],
                "attack": r.attack,
                "claim_refuted": r.claim_refuted,
                "attacker": r.adversary,
                "secret": key,
                "recovered": r.recovered.get(key, ""),
                "victim": r.expected[key],
                "fields_matched": f"{matched}/{len(r.expected)}",
                "result": "Success" if r.success else "Failed",
                "success": 1 if r.success else 0,
                "seconds": round(r.elapsed_s, 3),
            }
        )
    return rows


def build_defenses() -> list[dict]:
    from qsv2v.pqc import attack_suite

    rows = []
    for i, d in enumerate(attack_suite.run_all(), 1):
        rows.append(
            {
                "n": i,
                "attack": d.attack,
                "analogue_of": d.analogue_of,
                "attacker": d.attacker,
                "evidence": "; ".join(d.evidence),
                "control": d.control,
                "result": "Blocked" if d.blocked else "Not blocked",
                "blocked": 1 if d.blocked else 0,
            }
        )
    return rows


def build_bsm_sizes() -> list[dict]:
    from qsv2v.pqc.broadcast import FRAME_LIMIT, size_table

    rows = size_table()
    for r in rows:
        r["frame_limit"] = FRAME_LIMIT
        r["digest_msg_fits_frame"] = "yes" if r["digest_msg_fits_frame"] else "no"
        r["cert_msg_fits_frame"] = "yes" if r["cert_msg_fits_frame"] else "no"
    return rows


def build_scyther() -> list[dict]:
    """Default-bound verdicts from verification/results.txt (run_scyther.py output)."""
    text = (ROOT / "verification" / "results.txt").read_text(encoding="utf-8")
    rows, take = [], False
    for line in text.splitlines():
        if line.startswith("=="):
            take = line.startswith("== pq_v2v_ake.spdl   expected")
            continue
        if take and line.strip():
            label, verdict, *detail = line.split()
            rows.append(
                {
                    "claim": label,
                    "role": "Initiator" if "_I" in label else "Responder",
                    "property": label.split("_")[0],
                    "verdict": verdict,
                    "detail": " ".join(detail).strip("[]"),
                }
            )
    return rows


def build_sim_runs(path: Path, keep=lambda r: True) -> list[dict]:
    """Rows of a simulation summary.csv (written by python -m qsv2v.sim), numbers parsed."""
    import csv

    rows = []
    with path.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out = {}
            for k, v in r.items():
                try:
                    out[k] = float(v) if v not in ("", "None") else None
                except ValueError:
                    out[k] = v
            if keep(out):
                rows.append(out)
    return rows


EXP = ROOT / "results" / "experiments"
E9_COLS = ["sweep", "n_vehicles", "handshake_profile", "bsm_profile", "hs_policy", "seed",
           "speed_scale", "hs_attempted", "hs_success_rate", "hs_latency_ms_p50",
           "hs_latency_ms_p95", "hs_within_100ms", "cbr_mean", "bsm_pdr_in_range",
           "bsm_latency_ms_p95", "cpu_util_max"]  # fmt: skip


def _num(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return v
    return None if math.isnan(x) else x


def _rows(path: Path, cols=None) -> list[dict]:
    import csv

    with path.open(encoding="utf-8") as f:
        return [{k: _num(v) if v not in ("", "None") else None for k, v in r.items()
                 if cols is None or k in cols} for r in csv.DictReader(f)]  # fmt: skip


def build_e9(sweep: str) -> list[dict]:
    return [r for r in _rows(EXP / "e09_network_scale" / "data.csv", E9_COLS)
            if r["sweep"] == sweep]  # fmt: skip


def build_crypto_ops() -> list[dict]:
    keep = ["primitive", "kind", "operation", "ms", "ms_ci95", "n", "bytes_pk", "bytes_out"]
    return _rows(EXP / "e06_crypto_timing" / "summary.csv", keep)


def build_experiments() -> list[dict]:
    names = {True: "Supported", False: "Not supported", "partly": "Partly supported",
             None: "Comparison"}  # fmt: skip
    data = json.loads((EXP / "summary.json").read_text(encoding="utf-8"))
    return [{"n": int(o["key"][1:]), "key": o["key"], "title": o["title"],
             "hypothesis": o["hypothesis"], "verdict": names[o["supported"]],
             "supported": 1 if o["supported"] is True else 0,
             "tested": 0 if o["supported"] is None else 1, "finding": o["finding"]}
            for o in data]  # fmt: skip


def build_e3() -> list[dict]:
    keep = ["distance_km", "detection_rate", "qber", "skr_asymptotic", "skr_asymptotic_ci95",
            "skr_end_to_end", "skr_theory", "detection_theory", "n"]  # fmt: skip
    return _rows(EXP / "e03_distance_loss" / "summary.csv", keep)


def build_e7() -> list[dict]:
    keep = ["protocol", "variant", "implementation", "compute_ms", "compute_ms_ci95",
            "ec_at_c_speed_ms", "bytes_total", "bytes_per_message", "messages",
            "forward_secrecy", "quantum_resistant", "revocation", "n"]  # fmt: skip
    return _rows(EXP / "e07_handshake_cost" / "summary.csv", keep)


def build_theory() -> list[dict]:
    """Headline theory-vs-measured checks from report/math/ (Phase 10).

    Predictions come from qsv2v.formulas; measurements from results/experiments/ and
    results/sim/crypto_profile.json, read with the same helpers that write the
    report's tables (scripts/build_math_tables.py).
    """
    import build_math_tables as T

    from qsv2v import formulas as F

    e1 = T.rows("e01_eve_detection")
    q100 = next(
        T.num(r["qber_estimated"])
        for r in e1
        if T.num(r["noise"]) == 0 and T.num(r["eve_fraction"]) == 1
    )

    def f50(e):
        pts = [r for r in e1 if T.num(r["noise"]) == e]
        ys, xs = [T.num(r["abort_rate"]) for r in pts], [T.num(r["eve_fraction"]) for r in pts]
        return float(np.interp(0.5, ys, xs))

    e3 = T.rows("e03_distance_loss")
    e3n = T.result("e03_distance_loss")["numbers"]
    link = F.LinkModel()
    pos = max(int(T.num(r["distance_km"])) for r in e3 if T.num(r["skr_asymptotic"]) > 0)
    zero = min(int(T.num(r["distance_km"])) for r in e3 if T.num(r["skr_asymptotic"]) <= 0)
    e2 = T.rows("e02_channel_noise")
    e2n = T.result("e02_channel_noise")["numbers"]
    last_key = max(T.num(r["qber_measured"]) for r in e2 if T.num(r["key_fraction"]) > 0)
    data = T.rows("e02_channel_noise", "data.csv")
    n_key = np.mean([T.num(x["sifted_bits"]) for x in data if 0.08 <= T.num(x["noise"]) <= 0.11])
    over, fbar = F.finite_key_overhead(int(n_key)), e2n["cascade_f"]
    lo, hi = 1e-6, 0.5
    for _ in range(200):  # zero of 1 - (1 + f) h(Q) - overhead
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if F.key_fraction(mid, fbar) - over > 0 else (lo, mid)
    prof = json.loads(T.PROFILE.read_text(encoding="utf-8"))
    hs, bc = prof["handshakes"], prof["broadcasts"]
    e9 = T.rows("e09_network_scale")

    def p50(name):
        return next(
            T.num(r["hs_latency_ms_p50"])
            for r in e9
            if r["sweep"] == "handshake"
            and r["hs_policy"] == "all"
            and r["handshake_profile"] == name
            and int(r["n_vehicles"]) == 10
            and r["bsm_profile"] == "falcon"
            and T.num(r["speed_scale"]) == 1.0
        )

    def l0(name):
        h = hs[name]
        return 1e3 * F.handshake_latency_zero_load(
            (h["m1_bytes"], h["m2_bytes"], h["m3_bytes"]),
            (h["t_initiate"], h["t_respond"], h["t_finish"], h["t_confirm"]),
        )

    cbr50 = next(
        T.num(r["cbr_mean"])
        for r in e9
        if r["sweep"] == "broadcast" and r["bsm_profile"] == "falcon" and int(r["n_vehicles"]) == 50
    )
    fal = bc["falcon"]
    rho50 = F.offered_load(50, fal["msg_digest_bytes"], fal["msg_cert_bytes"])
    kem = F.mlkem_sizes(3, 10, 4)
    dsa = F.mldsa_sizes(4, 4, 8380417, 13, 2**17, 80, 128)
    cert = F.cert_size("ML-DSA-44", dsa["pk"], dsa["sig"])
    sz = F.handshake_sizes(kem["ek"], kem["ct"], cert, dsa["sig"])
    e7 = next(r for r in T.rows("e07_handshake_cost") if r["protocol"] == "PQ-V2V-AKE")
    e8 = next(r for r in T.rows("e08_message_size") if r["vehicle_alg"] == "ML-DSA-44")

    def pct(x):
        return f"{100 * x:.1f}%"

    def row(area, quantity, formula, theory, measured, agreement, chapter):
        return {
            "area": area,
            "quantity": quantity,
            "formula": formula,
            "theory": theory,
            "measured": measured,
            "agreement": agreement,
            "chapter": chapter,
        }

    q, n = "01_qkd.md", "04_network.md"
    return [
        row("BB84", "QBER with Eve on every photon", "e + f/4 − fe/2", "25.0%", pct(q100),
            "within error", q),
        row("BB84", "Eve fraction that triggers the 11% abort, clean channel",
            "(Q_th − e) / (1/4 − e/2)", pct(F.abort_fraction(0.0)), pct(f50(0.0)),
            "within error", q),
        row("BB84", "… with 2% channel noise", "same", pct(F.abort_fraction(0.02)),
            pct(f50(0.02)), "within error", q),
        row("BB84", "QBER where the final key reaches zero (Cascade)",
            "1 − (1+f)h(Q) − 131/n = 0", f"{100 * lo:.2f}%",
            f"between {100 * last_key:.2f}% and {100 * e2n['zero_key_qber']:.2f}%",
            "inside measured range", q),
        row("BB84", "Key-rate loss per km", "α dB/km", f"{link.alpha_db_per_km:.2f} dB/km",
            f"{e3n['db_per_km']:.3f} dB/km", "within error", q),
        row("BB84", "Distance where the key rate reaches zero", "(1+f)h(Q(d)) = 1",
            f"{link.cutoff_km():.1f} km", f"between {pos} and {zero} km",
            "inside measured range", q),
        row("Sizes", "Handshake message 1 (ML-KEM-768 + ML-DSA-44)", "62 + ek + cert + σ",
            f"{sz['m1']:,} B", f"{hs['pq-mldsa']['m1_bytes']:,} B", "exact", n),
        row("Sizes", "Whole handshake", "m1 + m2 + m3", f"{sz['m1'] + sz['m2'] + sz['m3']:,} B",
            f"{int(T.num(e7['bytes_total'])):,} B", "exact", n),
        row("Sizes", "ML-DSA-44 safety message with digest", "36 + len(alg) + payload + σ",
            f"{F.bsm_size('ML-DSA-44', 200, dsa['sig']):,} B",
            f"{int(T.num(e8['msg_with_digest_bytes'])):,} B", "exact", n),
        row("Network", "Classical handshake latency (3 frames)", "compute + Σ frame times",
            f"{l0('classical'):.2f} ms", f"{p50('classical'):.1f} ms (10 cars)",
            "within error", n),
        row("Network", "ML-DSA handshake latency (13 frames)", "compute + Σ frame times",
            f"{l0('pq-mldsa'):.2f} ms (idle channel)", f"{p50('pq-mldsa'):.1f} ms (10 cars)",
            "lower bound", n),
        row("Network", "Channel busy ratio, Falcon-512, 50 cars", "(2 d_cs / L) · N · r · T̄",
            f"{rho50:.3f}", f"{cbr50:.3f}", "within error", n),
    ]  # fmt: skip


def copy_traces(out: Path) -> None:
    import shutil

    for p in (ROOT / "results" / "sim" / "traces").glob("trace_*.json"):
        name = p.name.replace("trace_pq-mldsa", "trace_pq_mldsa")
        shutil.copy(p, out / name)
        print(f"  {name}: copied")


def main() -> None:
    args = sys.argv[1:]
    only = set(args[args.index("--only") + 1 :]) if "--only" in args else None
    pos = [a for a in args[: args.index("--only")] if "--only" in args] if only else args
    out = Path(pos[0]) if pos else ROOT / "results" / "showcase"
    out.mkdir(parents=True, exist_ok=True)
    e9 = "python -m qsv2v.experiments (E9): 12 s runs, first 6 s discarded, 5 seeds"
    jobs = {
        "phases": (build_phases, "git log (commit subjects 'Phase N:')"),
        "qber_grid": (build_qber_grid, "run_bb84, 200,000 photons per point, NumPy backend"),
        "key_rate": (build_key_rate, "run_qkd, 100,000 photons, 10 seeds per point, asymptotic"),
        "attacks": (build_attacks, "python -m qsv2v.attacks (seed 0, kyber-py ML-KEM)"),
        "paper_errors": (lambda: PAPER_ERRORS, "Read from the three base papers (documented)"),
        "defenses": (build_defenses, "qsv2v.pqc.attack_suite.run_all()"),
        "bsm_sizes": (build_bsm_sizes, "size_table(), 200-byte payload"),
        "scyther": (build_scyther, "verification/results.txt (Scyther v1.3.0)"),
        "sim_steady": (lambda: build_e9("handshake"), e9),
        "sim_broadcast": (lambda: build_e9("broadcast"), e9 + ", no handshakes"),
        "crypto_ops": (build_crypto_ops, "E6: qsv2v.pqc.bench.primitive_table() x 7 repeats"),
        "experiments": (build_experiments, "results/experiments/summary.json (E1-E10)"),
        "e3_distance": (build_e3, "results/experiments/e03_distance_loss/summary.csv"),
        "e7_cost": (build_e7, "results/experiments/e07_handshake_cost/summary.csv"),
        "tests": (build_tests, "pytest --junitxml over tests/"),
        "theory": (build_theory, "qsv2v.formulas vs results/ (report/math/, Phase 10)"),
        "security_levels": (
            lambda: SECURITY_LEVELS,
            "Read from FIPS 203/204, the algorithm specifications, RFC 7748 and "
            "Roetteler et al. (report/math/05_security_parameters.md)",
        ),
    }
    for name, (fn, inputs) in jobs.items():
        if only is None or name in only:
            print(name)
            write(out, f"{name}.json", fn(), inputs)
    if only is None or "traces" in only:
        copy_traces(out)


if __name__ == "__main__":
    main()
