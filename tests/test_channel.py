import numpy as np

from qsv2v.qkd.channel import QuantumChannel
from qsv2v.qkd.states import QubitBatch


def test_ideal_channel_is_identity(rng):
    batch = QubitBatch(rng.integers(0, 2, 100), rng.integers(0, 2, 100))
    out = QuantumChannel().transmit(batch, rng)
    np.testing.assert_array_equal(out.bits, batch.bits)
    np.testing.assert_array_equal(out.bases, batch.bases)
    assert out.detected.all()


def test_channel_does_not_alias_input(rng):
    batch = QubitBatch([0, 1], [0, 1])
    out = QuantumChannel().transmit(batch, rng)
    out.bits[0] = 1
    assert batch.bits[0] == 0
