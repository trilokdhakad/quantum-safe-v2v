import numpy as np
import pytest

from qsv2v.qkd.states import QubitBatch


def test_defaults_all_detected():
    b = QubitBatch([0, 1, 1], [1, 0, 1])
    assert b.bits.dtype == np.uint8
    assert b.detected.tolist() == [True, True, True]
    assert len(b) == 3


def test_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        QubitBatch([0, 1], [0])


def test_rejects_non_binary_values():
    with pytest.raises(ValueError):
        QubitBatch([0, 2], [0, 1])


def test_rejects_bad_detected_shape():
    with pytest.raises(ValueError):
        QubitBatch([0, 1], [0, 1], detected=[True])


def test_copy_is_independent():
    b = QubitBatch([0, 1], [0, 1])
    c = b.copy()
    c.bits[0] = 1
    c.detected[1] = False
    assert b.bits[0] == 0 and b.detected[1]
