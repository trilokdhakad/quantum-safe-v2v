"""Run Scyther on the PQ-V2V-AKE model and its sanity models; check every verdict.

    python verification/run_scyther.py [path/to/scyther-w32.exe]

The Scyther binary comes from the SCYTHER environment variable or the first
argument. Results are written to verification/results.txt.

Expected verdicts:

* pq_v2v_ake.spdl                              all 12 claims Ok
* sanity/negative_control_no_responder_sig     initiator claims Fail (MITM): the
                                               model CAN detect a broken protocol
* sanity/builtin_pk_authenticated_ok           Ok   (built-in pk/sk is asymmetric)
* sanity/builtin_pk_unauthenticated_fails      Fail (sanity: unauthenticated key)
* sanity/user_inversekeys_broken               Fail -- documents that Scyther
                                               v1.3.0 treats a user-declared
                                               inversekeys pair as symmetric,
                                               which is why the model uses pk/sk
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANSI = re.compile(r"\x1b\[[0-9;]*m")

EXPECT = {
    "pq_v2v_ake.spdl": "all_ok",
    "sanity/negative_control_no_responder_sig.spdl": "some_fail",
    "sanity/builtin_pk_authenticated_ok.spdl": "all_ok",
    "sanity/builtin_pk_unauthenticated_fails.spdl": "some_fail",
    "sanity/user_inversekeys_broken.spdl": "some_fail",
}


def run(scyther: str, model: str, extra: list[str]) -> list[tuple[str, str, str]]:
    out = subprocess.run(
        [scyther, *extra, model], cwd=HERE, capture_output=True, text=True, timeout=1200
    ).stdout
    claims = []
    for line in ANSI.sub("", out).splitlines():
        parts = line.split("\t")
        if parts and parts[0] == "claim" and len(parts) >= 6:
            claims.append((parts[2], parts[4], parts[5]))  # label, Ok/Fail, detail
    return claims


def main() -> int:
    scyther = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SCYTHER")
    if not scyther or not Path(scyther).exists():
        print("Scyther not found: pass its path or set SCYTHER", file=sys.stderr)
        return 2
    report, ok_all = [], True
    runs = [(m, e, []) for m, e in EXPECT.items()]
    runs += [("pq_v2v_ake.spdl", "all_ok", ["--max-runs=7"])]
    runs += [("pq_v2v_ake.spdl", "all_ok", ["--unbounded"])]
    for model, expect, extra in runs:
        claims = run(scyther, model, extra)
        verdicts = [c[1] for c in claims]
        got = "all_ok" if claims and all(v == "Ok" for v in verdicts) else "some_fail"
        good = bool(claims) and got == expect
        ok_all &= good
        report.append(
            f"== {model} {' '.join(extra)}  expected {expect}: {'PASS' if good else 'UNEXPECTED'}"
        )
        report += [f"   {label:14s} {v:4s}  {d}" for label, v, d in claims]
    text = "\n".join(report)
    (HERE / "results.txt").write_text(text + "\n", encoding="utf-8")
    print(text)
    print("\nall verdicts as expected" if ok_all else "\nSOME VERDICTS UNEXPECTED")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
