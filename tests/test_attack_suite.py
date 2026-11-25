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


@pytest.mark.parametrize("seed", [3, 7, 18, 28, 106, 306])
def test_linking_blocked_on_seeds_that_once_gave_false_positives(seed):
    """Seeds where the exact-match rule flagged chance 1-byte / zero-padding coincidences."""
    r = S.linking(seed)
    assert r.blocked, r.report()


def test_novelty_rule_catches_a_real_identifier_but_not_coincidences():
    rnd = bytes(range(37, 37 + 16))  # a 16-byte random-looking identifier
    other = bytes(200) + b"QSV2V-PSEUDONYM-HEADER" + bytes(200)
    # A real identifier absent from the other vehicle's message is novel.
    assert S._novel({rnd}, other, 16, 8) == {rnd}
    # A window that is the other vehicle's window plus one coincidental byte is not.
    near = b"\x99" + other[200:215]
    assert S._novel({near}, other, 16, 8) == set()
