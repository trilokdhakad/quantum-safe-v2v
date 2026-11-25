import numpy as np
import pytest

from qsv2v.attacks import shor_demo as S


def test_modmul_unitary_is_permutation():
    U = S.modmul_unitary(7, 15, 4)
    assert (U.sum(axis=0) == 1).all() and (U.sum(axis=1) == 1).all()
    np.testing.assert_array_equal(U @ U.T, np.eye(16))
    assert U[7, 1] == 1 and U[15, 15] == 1  # 7*1 mod 15; y >= N untouched


def test_classical_period():
    assert S.classical_period(7, 15) == 4
    assert S.classical_period(2, 21) == 6


@pytest.mark.parametrize("a,period", [(2, 4), (7, 4), (11, 2), (13, 4)])
def test_quantum_period_finding_n15(a, period):
    out = S.shor(15, a, shots=256, seed=1)
    assert out["period"] == period
    assert out["factors"] == (3, 5)


def test_a_with_minus_one_root_gives_no_factors():
    out = S.shor(15, 14, shots=256, seed=1)  # 14 = -1 mod 15, period 2
    assert out["period"] == 2 and out["factors"] is None


def test_demo_n15():
    r = S.demo_shor(15)
    assert r.success, r.report()


def test_rejects_non_coprime():
    with pytest.raises(ValueError):
        S.shor(15, 5)
