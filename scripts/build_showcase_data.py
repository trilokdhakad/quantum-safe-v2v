"""Build the datasets behind the project-progress page from real runs of this codebase.

    python scripts/build_showcase_data.py [out_dir]

Writes JSON files {rows, meta} to results/showcase/ (default):

* phases.json        -- phase status, read from git commit subjects "Phase N: ..."
* tests.json         -- pytest results per test file (runs the whole suite)
* qber_grid.json     -- BB84 QBER measured vs exact theory, noise x Eve fraction
* key_rate.json      -- final-key fraction vs QBER, with Cascade efficiency
* attacks.json       -- the eight Phase 4 attacks: recovered value vs victim's
* paper_errors.json  -- printing errors found in the base papers (documented)

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


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results" / "showcase"
    out.mkdir(parents=True, exist_ok=True)
    print("phases")
    write(out, "phases.json", build_phases(), "git log (commit subjects 'Phase N:')")  # noqa: E501,E702
    print("qber grid")
    write(
        out,
        "qber_grid.json",
        build_qber_grid(),
        "run_bb84, 200,000 photons per point, NumPy backend",
    )  # noqa: E501,E702
    print("key rate")
    write(
        out,
        "key_rate.json",
        build_key_rate(),
        "run_qkd, 100,000 photons, 10 seeds per point, asymptotic mode",
    )  # noqa: E501,E702
    print("attacks")
    write(out, "attacks.json", build_attacks(), "python -m qsv2v.attacks (seed 0, kyber-py ML-KEM)")  # noqa: E501,E702
    write(
        out,
        "paper_errors.json",
        PAPER_ERRORS,
        "Read from the three base papers (documented, not computed)",
    )  # noqa: E501
    print("tests")
    write(out, "tests.json", build_tests(), "pytest --junitxml over tests/")  # noqa: E501,E702


if __name__ == "__main__":
    main()
