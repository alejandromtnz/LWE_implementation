"""Graficas para los experimentos LWE."""

from __future__ import annotations

import os
from pathlib import Path

_DEFAULT_MPLCONFIGDIR = Path(__file__).resolve().parent / "results" / ".matplotlib"
_DEFAULT_MPLCONFIGDIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_DEFAULT_MPLCONFIGDIR))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def _save_figure(fig: plt.Figure, output_base: Path) -> None:
    output_base.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_base.with_suffix(".png"), dpi=180, bbox_inches="tight")
    fig.savefig(output_base.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(fig)


def plot_failure_vs_sigma(summary: pd.DataFrame, output_base: str | Path) -> None:
    data = summary.sort_values("sigma")
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.errorbar(
        data["sigma"],
        data["failure_rate_mean"],
        yerr=data.get("failure_rate_ci95", 0),
        fmt="o-",
        capsize=3,
        color="#2f6f9f",
        linewidth=1.8,
    )
    ax.set_xlabel("sigma del error")
    ax.set_ylabel("tasa de fallo de descifrado")
    ax.set_title("Fallo de descifrado frente al ruido")
    ax.grid(True, alpha=0.28)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    _save_figure(fig, Path(output_base))


def plot_failure_vs_q(summary: pd.DataFrame, output_base: str | Path) -> None:
    data = summary.sort_values("q")
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.errorbar(
        data["q"],
        data["failure_rate_mean"],
        yerr=data.get("failure_rate_ci95", 0),
        fmt="o-",
        capsize=3,
        color="#8a5a24",
        linewidth=1.8,
    )
    ax.set_xlabel("modulo q")
    ax.set_ylabel("tasa de fallo de descifrado")
    ax.set_title("Fallo de descifrado frente al modulo q")
    ax.grid(True, alpha=0.28)
    ax.set_ylim(bottom=0)
    fig.tight_layout()
    _save_figure(fig, Path(output_base))


def plot_cost_vs_n(summary: pd.DataFrame, output_base: str | Path) -> None:
    data = summary.sort_values("n")
    total_encrypt_decrypt = data["time_encrypt_mean_s_mean"] + data["time_decrypt_mean_s_mean"]

    fig, axes = plt.subplots(1, 2, figsize=(10.4, 4.4))

    axes[0].plot(data["n"], data["time_keygen_s_mean"], "o-", label="keygen", color="#2f6f9f")
    axes[0].plot(data["n"], data["time_encrypt_mean_s_mean"], "s-", label="encrypt por bit", color="#5a8f3b")
    axes[0].plot(data["n"], data["time_decrypt_mean_s_mean"], "^-", label="decrypt por bit", color="#9f3f3f")
    axes[0].plot(data["n"], total_encrypt_decrypt, "d--", label="encrypt+decrypt", color="#5b4c9a")
    axes[0].set_xlabel("dimension n")
    axes[0].set_ylabel("tiempo medio (s)")
    axes[0].set_title("Coste temporal")
    axes[0].grid(True, alpha=0.28)
    axes[0].legend(frameon=False, fontsize=8)

    axes[1].plot(
        data["n"],
        data["public_key_size_bytes_mean"] / 1024,
        "o-",
        color="#476a6f",
        linewidth=1.8,
    )
    axes[1].set_xlabel("dimension n")
    axes[1].set_ylabel("tamano aprox. clave publica (KiB)")
    axes[1].set_title("Crecimiento de la clave publica")
    axes[1].grid(True, alpha=0.28)

    fig.tight_layout()
    _save_figure(fig, Path(output_base))


def plot_decryption_histogram(samples: pd.DataFrame, output_base: str | Path) -> None:
    q = int(samples["q"].iloc[0])
    half = q // 2
    bins = np.arange(-0.5, q + 0.5, 1)
    if q > 300:
        bins = min(80, q)

    fig, axes = plt.subplots(1, 2, figsize=(11.0, 4.4))

    for bit, color in [(0, "#2f6f9f"), (1, "#9f3f3f")]:
        subset = samples[samples["bit"] == bit]
        axes[0].hist(
            subset["d"],
            bins=bins,
            alpha=0.55,
            density=True,
            label=f"mu={bit}",
            color=color,
        )
    axes[0].axvline(0, color="#333333", linestyle=":", linewidth=1.2)
    axes[0].axvline(half, color="#333333", linestyle="--", linewidth=1.2)
    axes[0].set_xlabel("d = v - <u,s> mod q")
    axes[0].set_ylabel("densidad")
    axes[0].set_title("Valores de descifrado")
    axes[0].legend(frameon=False)
    axes[0].grid(True, alpha=0.22)

    for bit, color in [(0, "#2f6f9f"), (1, "#9f3f3f")]:
        subset = samples[samples["bit"] == bit]
        axes[1].hist(
            subset["centered_noise"],
            bins=50,
            alpha=0.55,
            density=True,
            label=f"mu={bit}",
            color=color,
        )
    axes[1].axvline(-q / 4, color="#333333", linestyle=":", linewidth=1.2)
    axes[1].axvline(q / 4, color="#333333", linestyle=":", linewidth=1.2)
    axes[1].set_xlabel("ruido acumulado centrado")
    axes[1].set_ylabel("densidad")
    axes[1].set_title("Ruido relativo al centro esperado")
    axes[1].legend(frameon=False)
    axes[1].grid(True, alpha=0.22)

    fig.tight_layout()
    _save_figure(fig, Path(output_base))
