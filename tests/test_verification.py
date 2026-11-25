"""Formal verification: runs Scyther when it is available (set SCYTHER=path/to/scyther)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCYTHER = os.environ.get("SCYTHER")


def test_model_files_present():
    v = ROOT / "verification"
    assert (v / "pq_v2v_ake.spdl").exists()
    for name in [
        "negative_control_no_responder_sig",
        "builtin_pk_authenticated_ok",
        "builtin_pk_unauthenticated_fails",
        "user_inversekeys_broken",
    ]:
        assert (v / "sanity" / f"{name}.spdl").exists()
    model = (v / "pq_v2v_ake.spdl").read_text(encoding="utf-8").split("*/", 1)[1]
    assert "inversekeys" not in model  # see run_scyther.py for why


@pytest.mark.skipif(not SCYTHER or not Path(SCYTHER).exists(), reason="Scyther not available")
def test_scyther_verdicts():
    r = subprocess.run(
        [sys.executable, str(ROOT / "verification" / "run_scyther.py"), SCYTHER],
        capture_output=True,
        text=True,
        timeout=3600,
    )
    assert r.returncode == 0, r.stdout + r.stderr
