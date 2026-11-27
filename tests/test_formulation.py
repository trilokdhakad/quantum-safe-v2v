"""Phase 10: every derivation in report/math/ checked against independent evidence.

Each test names the report section it checks. The evidence is never the
formula itself: exact enumeration, the cryptographic libraries, the real
protocol encodings, the simulator, or fresh random instances of an attack.
"""

import math
import subprocess
import sys
from fractions import Fraction
from itertools import product
from pathlib import Path

import numpy as np
import pytest
from conftest import OQS, SEED

from qsv2v import formulas as F
from qsv2v.qkd import InterceptResendEve, PauliNoise, QuantumChannel
from qsv2v.qkd.bb84 import run_bb84
from qsv2v.qkd.cascade import cascade, initial_block_size
from qsv2v.qkd.estimation import estimate_qber
from qsv2v.qkd.privacy_amp import toeplitz_matrix
from qsv2v.qkd.theory import QBER_THRESHOLD, binary_entropy, expected_qber
from qsv2v.sim.radio import RadioConfig

ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# 1. BB84 (01_qkd.md)
# =============================================================================
def test_1_2_sift_probability_is_one_half():
    assert F.sift_probability() == Fraction(1, 2)


GRID = [Fraction(x, 100) for x in (0, 1, 3, 7, 10, 20)]


@pytest.mark.parametrize("f", [Fraction(x, 10) for x in range(0, 11, 2)])
def test_1_3_enumeration_equals_closed_form_exactly(f):
    """Theorem 1.1: the event-tree sum equals e_b + f/4 - f e_b/2, in exact arithmetic."""
    for e_r, e_d in product(GRID, GRID):
        q = F.qber_by_enumeration(e_r, e_d, f)
        closed = (e_r + f / 4 - f * e_r / 2 + e_d + f / 4 - f * e_d / 2) / 2
        assert q == closed


def test_1_3_enumeration_matches_theory_module_for_pauli_channels():
    for noise in (PauliNoise.bit_flip(0.06), PauliNoise.phase_flip(0.04),
                  PauliNoise(0.01, 0.02, 0.03), PauliNoise.depolarizing(0.1)):  # fmt: skip
        for f in (0.0, 0.3, 1.0):
            q = F.qber_by_enumeration(
                Fraction(noise.error_prob(0)), Fraction(noise.error_prob(1)), Fraction(f)
            )
            assert float(q) == pytest.approx(expected_qber(noise, f), abs=1e-12)


def test_1_3_asymmetric_noise_with_eve_matches_simulation():
    """Bit-flip noise only (e_+ = 8%, e_x = 0) plus Eve on 60%: an asymmetric case."""
    noise, f = PauliNoise.bit_flip(0.08), 0.6
    ch = QuantumChannel(noise=noise, eve=InterceptResendEve(f))
    r = run_bb84(400_000, channel=ch, seed=SEED)
    q = float(F.qber_by_enumeration(Fraction(8, 100), Fraction(0), Fraction(6, 10)))
    sigma = math.sqrt(q * (1 - q) / r.sifted_length)
    assert abs(r.qber - q) < 4 * sigma


def test_1_4_abort_point_solves_the_threshold_equation():
    for e in (0.0, 0.01, 0.02, 0.05):
        f = F.abort_fraction(e)
        assert F.qber_closed_form(e, f) == pytest.approx(QBER_THRESHOLD, abs=1e-15)
    assert F.abort_fraction(0.0) == pytest.approx(0.44)
    assert F.abort_fraction(0.02) == pytest.approx(0.375)


def test_1_4_abort_probability_matches_binomial_sampling():
    rng = np.random.default_rng(SEED)
    m = 2500
    for q in (0.10, 0.1125):
        rate = np.mean(rng.binomial(m, q, size=200_000) / m > QBER_THRESHOLD)
        assert rate == pytest.approx(F.abort_probability(q, m), abs=0.03)


def test_1_5_odd_parity_formula_equals_binomial_sum():
    for q, k in ((0.01, 73), (0.05, 15), (0.1, 8), (0.3, 5)):
        direct = sum(math.comb(k, j) * q**j * (1 - q) ** (k - j) for j in range(1, k + 1, 2))
        assert F.cascade_odd_block_prob(q, k) == pytest.approx(direct, rel=1e-12)


def test_1_5_first_cascade_pass_odd_blocks_match_prediction():
    n = 100_000
    for q in (0.02, 0.06):
        rng = np.random.default_rng(SEED)
        alice = rng.integers(0, 2, n, dtype=np.uint8)
        bob = alice ^ (rng.random(n) < q).astype(np.uint8)
        k = initial_block_size(q)
        res = cascade(alice, bob, q, rng)
        blocks = math.ceil(n / k)
        p = F.cascade_odd_block_prob(q, k)
        assert abs(res.parity_mismatches_per_pass[0] - blocks * p) < 4 * math.sqrt(
            blocks * p * (1 - p)
        )


@pytest.mark.parametrize("n,m", [(4, 2), (5, 3), (6, 2)])
def test_1_5_lemma2_toeplitz_collision_probability_is_exactly_2_to_minus_m(n, m):
    """For every nonzero z, exactly a 2^-m share of all seeds gives T z = 0 (exhaustive)."""
    seeds = list(product((0, 1), repeat=n + m - 1))
    for z in product((0, 1), repeat=n):
        if not any(z):
            continue
        zero = sum(
            not ((toeplitz_matrix(np.array(s), n, m) @ np.array(z)) % 2).any() for s in seeds
        )
        assert Fraction(zero, len(seeds)) == Fraction(1, 2**m)


def test_1_6_shor_preskill_and_cascade_thresholds():
    q = F.zero_key_qber(1.0)
    assert 1 - 2 * binary_entropy(q) == pytest.approx(0.0, abs=1e-9)
    assert q == pytest.approx(0.1100, abs=1e-4)
    assert F.zero_key_qber(1.19) == pytest.approx(0.0961, abs=2e-4)
    assert F.zero_key_qber(1.19) < F.zero_key_qber(1.1) < q  # worse code, lower threshold


def test_1_6_sampling_sigma_matches_simulated_qber_samples():
    """sigma_r = h'(Q) sigma_m: the spread of h(sampled QBER) over many disclosures."""
    rng = np.random.default_rng(SEED)
    n_sift, q = 50_000, 0.06
    alice = rng.integers(0, 2, n_sift, dtype=np.uint8)
    bob = alice ^ (rng.random(n_sift) < q).astype(np.uint8)
    q_true = float(np.mean(alice != bob))
    hs = [float(binary_entropy(estimate_qber(alice, bob, rng).qber)) for _ in range(1500)]
    m = round(0.1 * n_sift)
    # Sampling without replacement from a finite key shrinks the spread by sqrt(1 - m/n).
    pred = F.key_fraction_sampling_sigma(q_true, m) * math.sqrt(1 - m / n_sift)
    assert np.std(hs) == pytest.approx(pred, rel=0.08)


def test_1_6_clipped_mean_and_positive_probability_match_monte_carlo():
    rng = np.random.default_rng(SEED)
    for mu, s in ((0.0025, 0.0135), (-0.02, 0.0135), (0.04, 0.0135)):
        x = mu + s * rng.standard_normal(1_000_000)
        assert np.mean(np.maximum(0, x)) == pytest.approx(F.clipped_mean(mu, s), abs=5e-5)
        assert np.mean(x > 0) == pytest.approx(F.prob_positive(mu, s), abs=2e-3)


def test_1_7_key_rate_slope_and_cutoff():
    link = F.LinkModel()
    slope = (math.log10(link.key_rate(60)) - math.log10(link.key_rate(20))) / 40
    assert slope == pytest.approx(-link.alpha_db_per_km / 10, rel=0.01)
    d = link.cutoff_km()
    assert link.key_rate(d - 0.5) > 0 and link.key_rate(d + 0.5) == 0
    assert 180 < d < 185


def test_1_7_detection_rate_matches_simulation():
    link = F.LinkModel()
    ch = QuantumChannel(distance_km=50, detector_efficiency=0.2, dark_count_prob=1e-5)
    r = run_bb84(500_000, channel=ch, seed=SEED)
    p = link.eta(50) + (1 - link.eta(50)) * 1e-5
    assert abs(r.detection_rate - p) < 4 * math.sqrt(p * (1 - p) / r.n_sent)


# =============================================================================
# 2. Attacks (02_attacks.md)
# =============================================================================
def test_2_1_3_master_keys_from_two_certificates_random_instances():
    from qsv2v.crypto import Q

    rng = np.random.default_rng(SEED)
    for _ in range(50):
        x, y, h1, h2 = (int.from_bytes(rng.bytes(32), "big") % Q for _ in range(4))
        c1, c2 = (((1 + h) * x + y) % Q for h in (h1, h2))
        assert F.solve_master_keys(c1, c2, h1, h2, Q) == (x, y)
    with pytest.raises(ValueError):
        F.solve_master_keys(1, 2, 5, 5, Q)


def test_2_1_3_formula_agrees_with_the_attack_on_the_real_scheme():
    from qsv2v.attacks.psrs_d2d import attacks, protocol
    from qsv2v.crypto import DeterministicRNG, Q

    net = protocol.build_network(4, DeterministicRNG(7))
    a, b = net.drones[0], net.drones[1]
    pp = net.ta.public
    h1, h2 = protocol.cert_hash(a.Pub, a.ID, pp), protocol.cert_hash(b.Pub, b.ID, pp)
    got = F.solve_master_keys(a.Cert, b.Cert, h1, h2, Q)
    assert got == (net.ta.Pr_TA, net.ta.MK_TA) == attacks.extract_master_keys(a, b)


def test_2_2_2_expected_guesses():
    for d in (1, 2, 100, 20_000):
        assert F.expected_guesses(d) == Fraction(sum(range(1, d + 1)), d)


def test_2_4_shor_worked_example():
    from qsv2v.attacks.shor_demo import classical_period, period_from_phase

    assert classical_period(7, 15) == 4
    for y in (64, 128, 192):  # the non-zero peaks with 8 counting qubits
        assert period_from_phase(y, 8, 15, 7) == 4
    assert {math.gcd(7**2 - 1, 15), math.gcd(7**2 + 1, 15)} == {3, 5}


# =============================================================================
# 3/4. Sizes (04_network.md, 05_security_parameters.md)
# =============================================================================
def test_4_1_parameter_set_sizes_match_the_reference_implementations():
    from qsv2v.pqc.kem import MLKEM768
    from qsv2v.pqc.sig import MLDSA44

    kem = F.mlkem_sizes(3, 10, 4)
    kp = MLKEM768("kyber-py").keygen()
    ct, ss = MLKEM768("kyber-py").encaps(kp.public_key)
    assert (len(kp.public_key), len(kp.secret_key), len(ct), len(ss)) == (
        kem["ek"], kem["dk"], kem["ct"], kem["ss"])  # fmt: skip
    dsa = F.mldsa_sizes(4, 4, 8380417, 13, 2**17, 80, 128)
    s = MLDSA44()
    k = s.keygen()
    assert len(k.public_key) == dsa["pk"]
    assert len(s.sign(k.secret_key, b"x")) == dsa["sig"]


@pytest.mark.skipif(not OQS, reason="liboqs-python unavailable")
def test_4_1_sizes_match_liboqs():
    import oqs

    with oqs.KeyEncapsulation("ML-KEM-768") as k:
        d = k.details
        assert (d["length_public_key"], d["length_secret_key"], d["length_ciphertext"]) == (
            1184, 2400, 1088)  # fmt: skip
    with oqs.Signature("ML-DSA-44") as s:
        assert s.details["length_public_key"] == 1312
        assert s.details["length_signature"] == 2420
    with oqs.Signature("Falcon-512") as s:
        assert s.details["length_public_key"] == F.falcon_pk_size(512)


@pytest.mark.parametrize(
    "setup,x",
    [({}, 0), ({"hybrid": True}, 32), ({"sig_alg": "ECDSA-P256", "kem_alg": "X25519"}, 0)],
)
def test_4_2_handshake_sizes_match_real_transcripts(setup, x):
    from qsv2v.pqc import pq_v2v_ake as A

    net = A.setup_network(2, seed=1, n_pseudonyms=1, lifetime=10**6, **setup)
    tr = A.handshake(*net.vehicles, net.clock)
    cert = net.vehicles[0].credentials[0].cert
    assert len(cert) == F.cert_size(cert.sig_alg, len(cert.public_key), len(cert.signature))
    pred = F.handshake_sizes(len(tr.m1.ek), len(tr.m2.ct), len(cert), len(tr.m1.sig), x)
    assert pred == tr.sizes


def test_4_2_safety_message_sizes_match_real_messages():
    from qsv2v.crypto.rng import DeterministicRNG
    from qsv2v.pqc.broadcast import Broadcaster, bsm_payload
    from qsv2v.pqc.certs import Authority, enroll_vehicle
    from qsv2v.pqc.sig import get_scheme

    for alg in ("ECDSA-P256", "ML-DSA-44"):
        rng = DeterministicRNG(alg)
        ca = Authority(rng.fork("ca"), get_scheme(alg, rng=rng.fork("cas")))
        veh = get_scheme(alg, rng=rng.fork("v"))
        cred = enroll_vehicle(ca, b"VIN", veh, 1, 0, 300)[0]
        b = Broadcaster(cred, veh)
        full = b.sign(bsm_payload(0), 0, force_cert=True)
        dig = b.sign(bsm_payload(1), 0)
        sig = len(dig.signature)
        assert len(dig) == F.bsm_size(alg, 200, sig)
        assert len(full) == F.bsm_size(alg, 200, len(full.signature), len(cred.cert))


# =============================================================================
# 4. Radio channel and latency (04_network.md)
# =============================================================================
def test_4_3_airtime_constants():
    r = RadioConfig()
    assert r.airtime(1400) == pytest.approx(1965.333e-6, rel=1e-6)
    assert r.ack_time == pytest.approx(90.667e-6, rel=1e-4)
    assert F.frame_time(1400, True) == pytest.approx(110e-6 + 97.5e-6 + 1965.333e-6 + 90.667e-6)


def _two_car_handshake(seed: int):
    """The simulator's own handshake process on an empty road: two cars 10 m apart."""
    from test_sim import PROFILE, placed

    from qsv2v.sim.network import SimConfig, Simulation

    cfg = SimConfig(n_vehicles=2, seed=seed, radio=RadioConfig(comm_range=1e5))
    sim = Simulation(cfg, PROFILE)
    sim.hw = sim.medium.hw = placed([0.0, 10.0], [0.0, 0.0])
    sim.env.process(sim.handshake(0, 1))
    sim.env.run()
    (rec,) = sim.handshakes
    assert rec["success"]
    return rec


def test_4_4_idle_channel_latency_equals_formula():
    """Mean over seeds equals L0; every run lies between the all-zero and all-CW backoff bounds."""
    from test_sim import PROFILE

    hs = PROFILE.handshake("pq-mldsa")
    sizes = (hs.m1_bytes, hs.m2_bytes, hs.m3_bytes)
    comp = (hs.t_initiate, hs.t_respond, hs.t_finish, hs.t_confirm)
    r = RadioConfig()
    l0 = F.handshake_latency_zero_load(sizes, comp)
    frames = sum(len(r.fragments(s)) for s in sizes)
    cw, slot = r.cw_min_be, r.slot
    lo = l0 - frames * cw / 2 * slot
    hi = l0 + frames * cw / 2 * slot
    lat = np.array([_two_car_handshake(s)["latency"] for s in range(150)])
    assert np.all(lat >= lo - 1e-9) and np.all(lat <= hi + 1e-9)
    se = math.sqrt(frames * ((cw + 1) ** 2 - 1) / 12) * slot / math.sqrt(len(lat))
    assert abs(lat.mean() - l0) < 4 * se


def test_4_5_offered_load_matches_a_short_broadcast_simulation():
    from test_sim import PROFILE

    from qsv2v.sim.network import SimConfig, run

    b = PROFILE.broadcast("falcon")
    for n in (20, 40):
        # Averaged over placements: one random placement can cluster the cars (seed 3 at
        # n = 20 gives 0.06), the model predicts the mean over placements.
        cbr = np.mean([
            run(SimConfig(n_vehicles=n, duration=3.0, seed=s, handshake_profile=None,
                          bsm_profile="falcon"), PROFILE).summary["cbr_mean"]
            for s in range(6)
        ])  # fmt: skip
        rho = F.offered_load(n, b.msg_digest_bytes, b.msg_cert_bytes)
        assert cbr == pytest.approx(rho, rel=0.15)


# =============================================================================
# 5. Attack costs (05_security_parameters.md)
# =============================================================================
def test_5_generic_attack_costs():
    assert F.pollard_rho_bits(F.P256_ORDER) == pytest.approx(127.83, abs=0.01)
    assert F.grover_bits(128) == pytest.approx(63.65, abs=0.01)
    assert F.birthday_bits(256) == pytest.approx(128.33, abs=0.01)
    assert F.roetteler_qubits(256) == 2330  # as stated in Roetteler et al. 2017, Sec. 1


def test_5_core_svp_exponents_reproduce_the_specifications():
    """0.292 b (classical) and 0.265 b (quantum) on the specs' BKZ block sizes, to within 1 bit.

    The specifications round inconsistently (0.292 * 406 = 118.55 is reported as 118,
    0.292 * 626 = 182.79 as 183), so exact agreement is not expected.
    """
    for beta, c, q in ((406, 118, 107), (626, 183, 166), (423, 123, 112)):  # Kyber512/768, Dil2
        assert abs(0.292 * beta - c) <= 1 and abs(0.265 * beta - q) <= 1


# =============================================================================
# The generated tables in report/math/ are current
# =============================================================================
@pytest.mark.skipif(not (ROOT / "results" / "experiments" / "summary.json").exists(),
                    reason="run `python -m qsv2v.experiments` first")  # fmt: skip
def test_report_tables_match_recorded_results():
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_math_tables.py"), "--check"],
        capture_output=True, text=True, encoding="utf-8",
        env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
    )  # fmt: skip
    assert out.returncode == 0, out.stdout + out.stderr
