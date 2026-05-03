#!/usr/bin/env python3
"""
plot_results.py — visualise VDF benchmark CSV output.

Usage:
    python scripts/plot_results.py results/bench.csv

Produces two files next to the CSV:
    bench_timings.png   — eval_ms vs prove_ms dual-axis bar chart per T
    bench_proof_size.png — proof size comparison
"""

import sys
import os
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np


# ── Load ───────────────────────────────────────────────────────────────────────

def load(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    # Ensure columns are present
    required = {"construction", "t_effective", "eval_s", "prove_s",
                "proof_bytes", "verified"}
    missing = required - set(df.columns)
    if missing:
        sys.exit(f"CSV missing columns: {missing}")
    # Flag any failed verifications
    bad = df[~df["verified"]]
    if not bad.empty:
        print("WARNING: some proofs did NOT verify:")
        print(bad[["construction", "t_effective"]])
    return df


# ── Timing plot ────────────────────────────────────────────────────────────────

def plot_timings(df: pd.DataFrame, out_path: Path) -> None:
    constructions = df["construction"].unique()
    t_values = sorted(df["t_effective"].unique())
    n_t = len(t_values)

    fig, axes = plt.subplots(1, n_t, figsize=(5 * n_t, 6), sharey=False)
    if n_t == 1:
        axes = [axes]

    colors_eval  = {"Pietrzak": "#4C72B0", "Wesolowski": "#DD8452",
                    "SNARK-SHA256": "#55A868"}
    colors_prove = {"Pietrzak": "#64B5F6", "Wesolowski": "#FFCC80",
                    "SNARK-SHA256": "#A5D6A7"}

    for ax, t in zip(axes, t_values):
        sub = df[df["t_effective"] == t]
        x_pos = np.arange(len(constructions))
        width = 0.35

        eval_vals  = [sub.loc[sub["construction"] == c, "eval_s"].values[0]
                      if c in sub["construction"].values else 0
                      for c in constructions]
        prove_vals = [sub.loc[sub["construction"] == c, "prove_s"].values[0]
                      if c in sub["construction"].values else 0
                      for c in constructions]

        bars_e = ax.bar(x_pos - width / 2, eval_vals, width,
                        label="Eval", color=[colors_eval.get(c, "#999") for c in constructions])
        bars_p = ax.bar(x_pos + width / 2, prove_vals, width,
                        label="Prove", color=[colors_prove.get(c, "#ccc") for c in constructions])

        ax.set_title(f"T = {t:,}", fontsize=13, fontweight="bold")
        ax.set_xticks(x_pos)
        ax.set_xticklabels(constructions, rotation=15, ha="right", fontsize=9)
        ax.set_ylabel("Time (s)")
        ax.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.3f"))
        ax.legend(fontsize=8)
        ax.grid(axis="y", alpha=0.4)

        # Annotate bars with values
        for bar in list(bars_e) + list(bars_p):
            h = bar.get_height()
            if h > 0:
                ax.annotate(f"{h:.3f}",
                            xy=(bar.get_x() + bar.get_width() / 2, h),
                            xytext=(0, 3), textcoords="offset points",
                            ha="center", va="bottom", fontsize=7)

    fig.suptitle("VDF Construction Benchmarks — Eval vs Prove Time (seconds)",
                 fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved: {out_path}")
    plt.close()


# ── Proof size plot ────────────────────────────────────────────────────────────

def plot_proof_sizes(df: pd.DataFrame, out_path: Path) -> None:
    t_values      = sorted(df["t_effective"].unique())
    constructions = df["construction"].unique()

    fig, ax = plt.subplots(figsize=(9, 5))
    markers = {"Pietrzak": "o", "Wesolowski": "s", "SNARK-SHA256": "^"}
    colors  = {"Pietrzak": "#4C72B0", "Wesolowski": "#DD8452", "SNARK-SHA256": "#55A868"}

    for c in constructions:
        sub = df[df["construction"] == c].sort_values("t_effective")
        ax.plot(sub["t_effective"], sub["proof_bytes"],
                marker=markers.get(c, "x"),
                color=colors.get(c, "#777"),
                label=c, linewidth=2)

    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Delay parameter T (log₂ scale)", fontsize=11)
    ax.set_ylabel("Proof size (bytes, log scale)", fontsize=11)
    ax.set_title("Proof Size vs Delay Parameter", fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(which="both", alpha=0.3)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved: {out_path}")
    plt.close()


# ── Ratio plot ────────────────────────────────────────────────────────────────

def plot_prove_eval_ratio(df: pd.DataFrame, out_path: Path) -> None:
    """The key comparison: prove_time / eval_time ratio across T."""
    constructions = df["construction"].unique()
    t_values = sorted(df["t_effective"].unique())

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = {"Pietrzak": "#4C72B0", "Wesolowski": "#DD8452", "SNARK-SHA256": "#55A868"}

    for c in constructions:
        sub = df[df["construction"] == c].sort_values("t_effective")
        ratio = sub["prove_s"] / sub["eval_s"].replace(0, float("nan"))
        ax.plot(sub["t_effective"], ratio,
                marker="o", color=colors.get(c, "#777"),
                label=c, linewidth=2)

    ax.axhline(y=1.0, color="gray", linestyle="--", linewidth=1, label="prove = eval")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Delay parameter T (log₂ scale)", fontsize=11)
    ax.set_ylabel("prove_time / eval_time (log scale)", fontsize=11)
    ax.set_title("Proving Overhead Relative to Evaluation", fontsize=13,
                 fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(which="both", alpha=0.3)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.yaxis.set_major_formatter(ticker.ScalarFormatter())

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved: {out_path}")
    plt.close()


# ── Eval time comparison ──────────────────────────────────────────────────────

def plot_eval_comparison(df: pd.DataFrame, out_path: Path) -> None:
    """Eval time for all constructions on the same axes, across T values."""
    constructions = df["construction"].unique()
    colors  = {"Pietrzak": "#4C72B0", "Wesolowski": "#DD8452", "SNARK-SHA256": "#55A868"}
    markers = {"Pietrzak": "o", "Wesolowski": "s", "SNARK-SHA256": "^"}

    fig, ax = plt.subplots(figsize=(9, 5))

    for c in constructions:
        sub = df[df["construction"] == c].sort_values("t_effective")
        ax.plot(sub["t_effective"], sub["eval_s"],
                marker=markers.get(c, "x"),
                color=colors.get(c, "#777"),
                label=c, linewidth=2)

    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Delay parameter T (log₂ scale)", fontsize=11)
    ax.set_ylabel("Eval time (seconds, log scale)", fontsize=11)
    ax.set_title("Eval Time Comparison Across Constructions", fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(which="both", alpha=0.3)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved: {out_path}")
    plt.close()


# ── Prove time comparison ─────────────────────────────────────────────────────

def plot_prove_comparison(df: pd.DataFrame, out_path: Path) -> None:
    """Prove time for all constructions on the same axes, across T values."""
    constructions = df["construction"].unique()
    colors  = {"Pietrzak": "#4C72B0", "Wesolowski": "#DD8452", "SNARK-SHA256": "#55A868"}
    markers = {"Pietrzak": "o", "Wesolowski": "s", "SNARK-SHA256": "^"}

    fig, ax = plt.subplots(figsize=(9, 5))

    for c in constructions:
        sub = df[df["construction"] == c].sort_values("t_effective")
        ax.plot(sub["t_effective"], sub["prove_s"],
                marker=markers.get(c, "x"),
                color=colors.get(c, "#777"),
                label=c, linewidth=2)

    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Delay parameter T (log₂ scale)", fontsize=11)
    ax.set_ylabel("Prove time (seconds, log scale)", fontsize=11)
    ax.set_title("Prove Time Comparison Across Constructions", fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(which="both", alpha=0.3)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved: {out_path}")
    plt.close()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("Usage: plot_results.py <path/to/bench.csv>")

    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        sys.exit(f"File not found: {csv_path}")

    df = load(csv_path)
    base = csv_path.parent

    plot_timings(df,             base / "bench_timings.png")
    plot_proof_sizes(df,         base / "bench_proof_size.png")
    plot_prove_eval_ratio(df,    base / "bench_prove_eval_ratio.png")
    plot_eval_comparison(df,     base / "bench_eval_comparison.png")
    plot_prove_comparison(df,    base / "bench_prove_comparison.png")

    print("\nSummary table:")
    print(df[["construction", "t_effective", "eval_s", "prove_s",
              "proof_bytes", "verified"]].to_string(index=False))


if __name__ == "__main__":
    main()
