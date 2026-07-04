"""Experimentos reproducibles para el esquema LWE simplificado."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import Iterable, Optional

import numpy as np
import pandas as pd

from lwe_scheme import LWEScheme, centered_mod, solve_linear_system_mod_prime


@dataclass(frozen=True)
class ExperimentSetting:
    """Parametros de una familia de ensayos."""

    n: int
    q: int
    sigma: float = 0.0
    m: Optional[int] = None
    B: Optional[int] = None

    @property
    def actual_m(self) -> int:
        return self.m if self.m is not None else 2 * self.n


def _seed_sequence(seed: int) -> Iterable[int]:
    rng = np.random.default_rng(seed)
    while True:
        yield int(rng.integers(0, 2**32 - 1))


def _normal_ci95(values: np.ndarray) -> float:
    if values.size <= 1:
        return 0.0
    return float(1.96 * values.std(ddof=1) / np.sqrt(values.size))


def summarize_repeats(raw: pd.DataFrame, group_columns: list[str]) -> pd.DataFrame:
    """Resume repeticiones independientes con medias e IC 95% sencillos."""

    metric_columns = [
        "success_rate",
        "failure_rate",
        "accumulated_error_mean",
        "accumulated_abs_error_mean",
        "accumulated_error_std",
        "time_keygen_s",
        "time_encrypt_mean_s",
        "time_decrypt_mean_s",
        "time_attack_s",
        "attack_solution_found",
        "attack_success",
        "public_key_size_bytes",
    ]

    rows: list[dict[str, object]] = []
    for keys, group in raw.groupby(group_columns, dropna=False, sort=False):
        if not isinstance(keys, tuple):
            keys = (keys,)
        row: dict[str, object] = dict(zip(group_columns, keys))
        row["repeats"] = int(len(group))
        row["trials_total"] = int(group["trials"].sum())
        row["successes_total"] = int(group["successes"].sum())
        row["failures_total"] = int(group["failures"].sum())

        for metric in metric_columns:
            if metric not in group:
                continue
            values = group[metric].dropna().to_numpy(dtype=float)
            if values.size == 0:
                continue
            row[f"{metric}_mean"] = float(values.mean())
            row[f"{metric}_std"] = float(values.std(ddof=1)) if values.size > 1 else 0.0
            row[f"{metric}_ci95"] = _normal_ci95(values)

        rows.append(row)

    return pd.DataFrame(rows)


def run_decryption_repeat(
    setting: ExperimentSetting,
    trials: int,
    seed: int,
    experiment: str,
    repeat: int,
    case: str = "",
    run_attack: bool = False,
) -> dict[str, object]:
    """Ejecuta una repeticion: una clave, muchos cifrados y descifrados."""

    rng = np.random.default_rng(seed)
    scheme = LWEScheme(
        n=setting.n,
        m=setting.actual_m,
        q=setting.q,
        sigma=setting.sigma,
        B=setting.B,
        rng=rng,
    )

    start = time.perf_counter()
    keypair = scheme.keygen()
    time_keygen = time.perf_counter() - start

    attack_solution_found = np.nan
    attack_success = np.nan
    time_attack = np.nan
    if run_attack:
        start = time.perf_counter()
        recovered = solve_linear_system_mod_prime(keypair.public.A, keypair.public.b, setting.q)
        time_attack = time.perf_counter() - start
        attack_solution_found = recovered is not None
        attack_success = bool(recovered is not None and np.array_equal(recovered % setting.q, keypair.secret.s % setting.q))

    bits = rng.integers(0, 2, size=trials, dtype=np.int64)

    start = time.perf_counter()
    ciphertexts = [scheme.encrypt_bit(keypair.public, int(bit)) for bit in bits]
    time_encrypt = time.perf_counter() - start

    decrypted: list[int] = []
    accumulated_errors: list[int] = []
    start = time.perf_counter()
    for bit, ciphertext in zip(bits, ciphertexts):
        d = scheme.decryption_value(keypair.secret, ciphertext)
        decrypted.append(scheme.decrypt_from_value(d))
        accumulated_errors.append(int(centered_mod(d - int(bit) * scheme.message_gap, setting.q)))
    time_decrypt = time.perf_counter() - start

    decrypted_array = np.asarray(decrypted, dtype=np.int64)
    accumulated_array = np.asarray(accumulated_errors, dtype=np.int64)
    failures = int(np.count_nonzero(decrypted_array != bits))
    successes = int(trials - failures)

    return {
        "experiment": experiment,
        "case": case,
        "repeat": repeat,
        "seed": seed,
        "n": setting.n,
        "m": setting.actual_m,
        "q": setting.q,
        "sigma": setting.sigma,
        "B": setting.B if setting.B is not None else np.nan,
        "noise_model": "bounded" if setting.B is not None else "gaussian",
        "trials": trials,
        "successes": successes,
        "failures": failures,
        "success_rate": successes / trials,
        "failure_rate": failures / trials,
        "accumulated_error_mean": float(accumulated_array.mean()),
        "accumulated_abs_error_mean": float(np.abs(accumulated_array).mean()),
        "accumulated_error_std": float(accumulated_array.std(ddof=1)) if trials > 1 else 0.0,
        "time_keygen_s": time_keygen,
        "time_encrypt_total_s": time_encrypt,
        "time_decrypt_total_s": time_decrypt,
        "time_encrypt_mean_s": time_encrypt / trials,
        "time_decrypt_mean_s": time_decrypt / trials,
        "time_attack_s": time_attack,
        "attack_solution_found": attack_solution_found,
        "attack_success": attack_success,
        "public_key_size_bytes": scheme.public_key_size_bytes(),
    }


def _run_grid(
    settings: list[tuple[ExperimentSetting, str]],
    trials: int,
    repeats: int,
    seed: int,
    experiment: str,
    run_attack: bool = False,
) -> pd.DataFrame:
    seed_iter = _seed_sequence(seed)
    rows: list[dict[str, object]] = []
    for setting, case in settings:
        for repeat in range(repeats):
            rows.append(
                run_decryption_repeat(
                    setting=setting,
                    trials=trials,
                    seed=next(seed_iter),
                    experiment=experiment,
                    repeat=repeat,
                    case=case,
                    run_attack=run_attack,
                )
            )
    return pd.DataFrame(rows)


def experiment_noise_vs_no_noise(
    n: int = 64,
    q: int = 257,
    sigma_with_noise: float = 4.0,
    trials: int = 400,
    repeats: int = 10,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    settings = [
        (ExperimentSetting(n=n, q=q, sigma=0.0), "sin_ruido"),
        (ExperimentSetting(n=n, q=q, sigma=sigma_with_noise), "con_ruido"),
    ]
    raw = _run_grid(settings, trials, repeats, seed, "noise_vs_no_noise", run_attack=True)
    summary = summarize_repeats(raw, ["experiment", "case", "n", "m", "q", "sigma", "B", "noise_model"])
    return raw, summary


def experiment_noise_sweep(
    n: int = 64,
    q: int = 257,
    sigmas: Optional[list[float]] = None,
    trials: int = 400,
    repeats: int = 10,
    seed: int = 1001,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if sigmas is None:
        sigmas = [0, 0.5, 1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24]
    settings = [(ExperimentSetting(n=n, q=q, sigma=float(sigma)), f"sigma={sigma}") for sigma in sigmas]
    raw = _run_grid(settings, trials, repeats, seed, "noise_sweep")
    summary = summarize_repeats(raw, ["experiment", "n", "m", "q", "sigma", "B", "noise_model"])
    return raw, summary


def experiment_q_sweep(
    n: int = 64,
    qs: Optional[list[int]] = None,
    sigma: float = 4.0,
    trials: int = 400,
    repeats: int = 10,
    seed: int = 2001,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if qs is None:
        qs = [97, 193, 257, 389, 521, 769]
    settings = [(ExperimentSetting(n=n, q=int(q), sigma=sigma), f"q={q}") for q in qs]
    raw = _run_grid(settings, trials, repeats, seed, "q_sweep")
    summary = summarize_repeats(raw, ["experiment", "n", "m", "q", "sigma", "B", "noise_model"])
    return raw, summary


def experiment_n_sweep(
    ns: Optional[list[int]] = None,
    q: int = 257,
    sigma: float = 2.0,
    trials: int = 400,
    repeats: int = 10,
    seed: int = 3001,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if ns is None:
        ns = [16, 32, 64, 96, 128]
    settings = [(ExperimentSetting(n=int(n), q=q, sigma=sigma), f"n={n}") for n in ns]
    raw = _run_grid(settings, trials, repeats, seed, "n_sweep")
    summary = summarize_repeats(raw, ["experiment", "n", "m", "q", "sigma", "B", "noise_model"])
    return raw, summary


def experiment_decryption_histogram(
    n: int = 64,
    q: int = 257,
    sigma: float = 6.0,
    samples_per_bit: int = 4000,
    seed: int = 4001,
) -> pd.DataFrame:
    """Muestrea d = v - <u,s> mod q para mu=0 y mu=1."""

    rng = np.random.default_rng(seed)
    scheme = LWEScheme(n=n, q=q, sigma=sigma, rng=rng)
    keypair = scheme.keygen()
    rows: list[dict[str, object]] = []

    for bit in (0, 1):
        for index in range(samples_per_bit):
            ciphertext = scheme.encrypt_bit(keypair.public, bit)
            d = scheme.decryption_value(keypair.secret, ciphertext)
            centered_noise = int(centered_mod(d - bit * scheme.message_gap, q))
            rows.append(
                {
                    "experiment": "decryption_histogram",
                    "sample": index,
                    "bit": bit,
                    "n": n,
                    "m": 2 * n,
                    "q": q,
                    "sigma": sigma,
                    "d": d,
                    "message_center": bit * scheme.message_gap,
                    "centered_noise": centered_noise,
                    "decrypted": scheme.decrypt_from_value(d),
                    "failure": int(scheme.decrypt_from_value(d) != bit),
                }
            )

    return pd.DataFrame(rows)


def experiment_decryption_histogram_multikey(
    n: int = 64,
    q: int = 257,
    sigma: float = 6.0,
    n_keys: int = 40,
    samples_per_bit_per_key: int = 100,
    seed: int = 5001,
) -> pd.DataFrame:
    """Muestrea d usando varias claves independientes.

    Esta variante reduce el sesgo visual que puede aparecer al condicionar todo
    el histograma a una unica realizacion del vector de error e.
    """

    seed_rng = np.random.default_rng(seed)
    rows: list[dict[str, object]] = []

    for key_index in range(n_keys):
        key_seed = int(seed_rng.integers(0, 2**32 - 1))
        rng = np.random.default_rng(key_seed)
        scheme = LWEScheme(n=n, q=q, sigma=sigma, rng=rng)
        keypair = scheme.keygen()

        for bit in (0, 1):
            for sample_index in range(samples_per_bit_per_key):
                ciphertext = scheme.encrypt_bit(keypair.public, bit)
                d = scheme.decryption_value(keypair.secret, ciphertext)
                centered_noise = int(centered_mod(d - bit * scheme.message_gap, q))
                rows.append(
                    {
                        "experiment": "decryption_histogram_multikey",
                        "key_index": key_index,
                        "key_seed": key_seed,
                        "sample": sample_index,
                        "bit": bit,
                        "n": n,
                        "m": 2 * n,
                        "q": q,
                        "sigma": sigma,
                        "d": d,
                        "message_center": bit * scheme.message_gap,
                        "centered_noise": centered_noise,
                        "decrypted": scheme.decrypt_from_value(d),
                        "failure": int(scheme.decrypt_from_value(d) != bit),
                    }
                )

    return pd.DataFrame(rows)


def write_csv(df: pd.DataFrame, path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
