"""Script principal para generar resultados y graficas."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from experiments import (
    experiment_decryption_histogram,
    experiment_n_sweep,
    experiment_noise_sweep,
    experiment_noise_vs_no_noise,
    experiment_q_sweep,
    write_csv,
)
from plots import (
    plot_cost_vs_n,
    plot_decryption_histogram,
    plot_failure_vs_q,
    plot_failure_vs_sigma,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ejecuta experimentos de un esquema LWE simplificado."
    )
    parser.add_argument("--results-dir", default="results", help="Directorio de salida.")
    parser.add_argument("--seed", type=int, default=42, help="Semilla base reproducible.")
    parser.add_argument("--trials", type=int, default=400, help="Cifrados por repeticion.")
    parser.add_argument("--repeats", type=int, default=10, help="Repeticiones independientes.")
    parser.add_argument("--hist-samples", type=int, default=4000, help="Muestras por bit para histogramas.")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Ejecucion rapida para comprobar que todo funciona.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    results_dir = Path(args.results_dir)
    if not results_dir.is_absolute():
        results_dir = script_dir / results_dir
    results_dir.mkdir(parents=True, exist_ok=True)

    trials = 120 if args.quick else args.trials
    repeats = 4 if args.quick else args.repeats
    hist_samples = 800 if args.quick else args.hist_samples

    print(f"Resultados en: {results_dir}")
    print(f"Ensayos por repeticion: {trials}; repeticiones: {repeats}")

    comparison_raw, comparison_summary = experiment_noise_vs_no_noise(
        trials=trials,
        repeats=repeats,
        seed=args.seed,
    )
    write_csv(comparison_raw, results_dir / "comparison_noise_raw.csv")
    write_csv(comparison_summary, results_dir / "comparison_noise_summary.csv")
    print("OK comparacion sin ruido/con ruido")

    noise_raw, noise_summary = experiment_noise_sweep(
        trials=trials,
        repeats=repeats,
        seed=args.seed + 1,
    )
    write_csv(noise_raw, results_dir / "noise_sweep_raw.csv")
    write_csv(noise_summary, results_dir / "noise_sweep_summary.csv")
    plot_failure_vs_sigma(noise_summary, results_dir / "failure_vs_sigma")
    print("OK barrido de sigma")

    q_raw, q_summary = experiment_q_sweep(
        trials=trials,
        repeats=repeats,
        seed=args.seed + 2,
    )
    write_csv(q_raw, results_dir / "q_sweep_raw.csv")
    write_csv(q_summary, results_dir / "q_sweep_summary.csv")
    plot_failure_vs_q(q_summary, results_dir / "failure_vs_q")
    print("OK barrido de q")

    n_raw, n_summary = experiment_n_sweep(
        trials=trials,
        repeats=repeats,
        seed=args.seed + 3,
    )
    write_csv(n_raw, results_dir / "n_sweep_raw.csv")
    write_csv(n_summary, results_dir / "n_sweep_summary.csv")
    plot_cost_vs_n(n_summary, results_dir / "cost_vs_n")
    print("OK barrido de n")

    histogram = experiment_decryption_histogram(
        samples_per_bit=hist_samples,
        seed=args.seed + 4,
    )
    write_csv(histogram, results_dir / "histogram_d_values.csv")
    plot_decryption_histogram(histogram, results_dir / "histogram_d")
    print("OK histogramas de d")

    all_summaries = pd.concat(
        [
            comparison_summary,
            noise_summary,
            q_summary,
            n_summary,
        ],
        ignore_index=True,
        sort=False,
    )
    write_csv(all_summaries, results_dir / "all_summaries.csv")
    print("Experimentos completados.")


if __name__ == "__main__":
    main()
