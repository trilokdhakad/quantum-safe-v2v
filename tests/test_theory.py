import numpy as np
import pytest

from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.theory import (
    QBER_THRESHOLD,
    asymptotic_key_fraction,
    binary_entropy,
    detection_probability,
    expected_qber,
)


def test_binary_entropy_values():
    assert binary_entropy(0) == 0.0
    assert binary_entropy(1) == 0.0
    assert binary_entropy(0.5) == pytest.approx(1.0)
    assert binary_entropy(0.11) == pytest.approx(0.4999, abs=1e-3)
    np.testing.assert_allclose(binary_entropy(np.array([0.1, 0.9])), [0.469, 0.469], atol=1e-3)


def test_threshold_is_shor_preskill_zero():
    assert asymptotic_key_fraction(QBER_THRESHOLD) == pytest.approx(0.0, abs=2e-3)
    assert asymptotic_key_fraction(0.0) == 1.0
    assert asymptotic_key_fraction(0.2) == 0.0


def test_expected_qber_cases():
    assert expected_qber() == 0.0
    assert expected_qber(eve_fraction=1.0) == pytest.approx(0.25)
    assert expected_qber(PauliNoise.from_qber(0.05)) == pytest.approx(0.05)
    # Cross term: e + f/4 - f e / 2.
    assert expected_qber(PauliNoise.from_qber(0.1), 1.0) == pytest.approx(0.1 + 0.25 - 0.05)
    # Bit flip only hits rectilinear: average error p/2.
    assert expected_qber(PauliNoise.bit_flip(0.1)) == pytest.approx(0.05)


def test_expected_qber_dark_counts():
    assert expected_qber(eta=0.0, dark_count_prob=0.1) == pytest.approx(0.5)
    assert expected_qber(eta=0.0) == 0.0
    q = expected_qber(eta=0.1, dark_count_prob=0.01)
    assert q == pytest.approx(0.9 * 0.01 * 0.5 / (0.1 + 0.9 * 0.01))
    assert detection_probability(0.1, 0.01) == pytest.approx(0.109)
