"""Phase 5 'done when': every Phase 4 attack class fails against PQ-V2V-AKE."""

import pytest

from qsv2v.pqc import attack_suite as S


@pytest.mark.parametrize(
    "fn",
    [
        S.passive_key_recovery,
        S.forward_secrecy,
        S.capture_and_forge,
        S.forged_msg1,
        S.mitm_swap,
        S.linking,
        S.password_guessing,
        S.quantum_breaks_x25519,
    ],
    ids=lambda f: f.__name__,
)
def test_attack_blocked(fn):
    r = fn()
    assert r.blocked, r.report()


def test_forward_secrecy_positive_control():
    """The FS test is meaningful: with the ephemeral key the attacker WOULD win."""
    r = S.forward_secrecy()
    assert "IS recovered: True" in r.control


def test_linking_positive_control():
    """The linking test detects linkable traffic when it exists (same pseudonym)."""
    r = S.linking()
    assert "finds 0 " not in r.control and "identifying windows" in r.control
