"""Tests for the LWE toy cryptosystem.

These aren't smoke tests. Each one checks a specific claim the README makes:
correctness under noise, the noiseless-vs-noisy attack asymmetry that is the
whole point of the project, and the size/validation contracts of the scheme.

Run from src/:
    pip install pytest
    pytest -v
"""

from __future__ import annotations

import math

import numpy as np
import pandas as pd
import pytest

from lwe_scheme import (
    LWEScheme,
    centered_mod,
    is_prime,
    solve_linear_system_mod_prime,
)
from experiments import summarize_repeats


# ---------------------------------------------------------------------------
# centered_mod / is_prime — small pure functions, but everything else in the
# scheme (decryption threshold, the attack's residual check) depends on them
# being correct.
# ---------------------------------------------------------------------------

def test_centered_mod_scalar_stays_in_symmetric_range():
    q = 257
    for x in [0, 1, 128, 200, 256, 257, 1000]:
        c = centered_mod(x, q)
        assert -q // 2 < c <= q // 2

def test_centered_mod_matches_hand_computed_values():
    # q=7 -> half=3, representatives in (-3, 3]
    assert centered_mod(0, 7) == 0
    assert centered_mod(3, 7) == 3
    assert centered_mod(4, 7) == -3   # 4 mod 7, closest representative is -3
    assert centered_mod(10, 7) == 3   # 10 mod 7 = 3

def test_centered_mod_array_matches_scalar_elementwise():
    q = 97
    values = np.array([0, 10, 48, 49, 96, 200])
    array_result = centered_mod(values, q)
    scalar_result = [centered_mod(int(v), q) for v in values]
    assert list(array_result) == scalar_result

def test_is_prime_known_values():
    assert is_prime(2)
    assert is_prime(257)   # the scheme's default modulus
    assert is_prime(97)
    assert not is_prime(1)
    assert not is_prime(4)
    assert not is_prime(9)
    assert not is_prime(200)


# ---------------------------------------------------------------------------
# Parameter validation — the constructor is supposed to reject nonsensical
# configurations rather than silently producing garbage.
# ---------------------------------------------------------------------------

def test_rejects_non_prime_unsuitable_params():
    with pytest.raises(ValueError):
        LWEScheme(n=4, q=2)           # q must be > 2
    with pytest.raises(ValueError):
        LWEScheme(n=4, q=17, sigma=-1.0)   # negative noise makes no sense
    with pytest.raises(ValueError):
        LWEScheme(n=4, q=17, sigma=1.0, B=2)  # sigma and B are mutually exclusive


# ---------------------------------------------------------------------------
# Correctness — decrypt(encrypt(bit)) == bit, both in the noiseless case
# (must hold always) and under moderate noise (must hold with high
# probability, per the README's own sigma<=3 -> ~0% failure claim).
# ---------------------------------------------------------------------------

def test_roundtrip_is_exact_with_zero_noise():
    scheme = LWEScheme(n=32, q=97, sigma=0.0, seed=42)
    keypair = scheme.keygen()
    for bit in (0, 1):
        for _ in range(25):
            ciphertext = scheme.encrypt_bit(keypair.public, bit)
            assert scheme.decrypt_bit(keypair.secret, ciphertext) == bit

def test_roundtrip_succeeds_with_high_probability_under_moderate_noise():
    # n=64, q=257, sigma=2 are exactly the "safe window" values from the
    # thesis (sigma <= 3 -> failure well under 1%).
    scheme = LWEScheme(n=64, q=257, sigma=2.0, seed=7)
    keypair = scheme.keygen()
    rng = np.random.default_rng(123)
    bits = rng.integers(0, 2, size=300)
    successes = sum(
        scheme.decrypt_bit(keypair.secret, scheme.encrypt_bit(keypair.public, int(bit))) == bit
        for bit in bits
    )
    assert successes / len(bits) > 0.97


# ---------------------------------------------------------------------------
# The headline result: the exact linear-algebra attack recovers the secret
# every time when sigma=0, and (per the LWE hardness assumption this whole
# project is about) it does not when noise is present.
# ---------------------------------------------------------------------------

def test_attack_recovers_secret_exactly_without_noise():
    scheme = LWEScheme(n=16, q=97, sigma=0.0, seed=1)
    keypair = scheme.keygen()
    recovered = solve_linear_system_mod_prime(keypair.public.A, keypair.public.b, 97)
    assert recovered is not None
    assert np.array_equal(recovered % 97, keypair.secret.s % 97)

def test_attack_does_not_recover_secret_with_noise():
    scheme = LWEScheme(n=16, q=97, sigma=4.0, seed=1)
    keypair = scheme.keygen()
    recovered = solve_linear_system_mod_prime(keypair.public.A, keypair.public.b, 97)
    # Either the exact system is inconsistent (recovered is None) or, if a
    # solution is found, it must not equal the real secret. Either way, the
    # noiseless attack must NOT reconstruct s once noise is present -- this
    # is the empirical claim the whole README's headline result rests on.
    assert recovered is None or not np.array_equal(recovered % 97, keypair.secret.s % 97)

def test_solve_linear_system_rejects_composite_modulus():
    A = np.array([[1, 2], [3, 4]])
    b = np.array([1, 2])
    with pytest.raises(ValueError):
        solve_linear_system_mod_prime(A, b, 100)  # 100 is not prime


# ---------------------------------------------------------------------------
# public_key_size_bytes -- this is the number quoted in the README's
# "public key size vs n" table, so it needs a direct check against the
# formula (2n*n + n) samples * ceil(log2 q) bits, independent of the code
# that computes it.
# ---------------------------------------------------------------------------

def test_public_key_size_matches_formula():
    n, q = 64, 257
    scheme = LWEScheme(n=n, q=q, sigma=0.0, seed=0)
    bits_per_entry = math.ceil(math.log2(q))   # 9 bits for q=257
    m = 2 * n
    expected_bits = (m * n + m) * bits_per_entry
    expected_bytes = math.ceil(expected_bits / 8)
    assert scheme.public_key_size_bytes() == expected_bytes
    assert expected_bytes == 9360   # the exact value quoted in the README for n=64


# ---------------------------------------------------------------------------
# summarize_repeats -- the aggregation function behind every CSV in
# src/results/. A bug here would silently corrupt every reported number.
# ---------------------------------------------------------------------------

def test_summarize_repeats_aggregates_correctly():
    raw = pd.DataFrame({
        "n": [64, 64],
        "q": [257, 257],
        "trials": [100, 100],
        "successes": [100, 90],
        "failures": [0, 10],
        "success_rate": [1.0, 0.9],
        "failure_rate": [0.0, 0.1],
    })
    summary = summarize_repeats(raw, ["n", "q"])
    assert len(summary) == 1
    row = summary.iloc[0]
    assert row["repeats"] == 2
    assert row["trials_total"] == 200
    assert row["successes_total"] == 190
    assert row["success_rate_mean"] == pytest.approx(0.95)
    assert row["failure_rate_mean"] == pytest.approx(0.05)
