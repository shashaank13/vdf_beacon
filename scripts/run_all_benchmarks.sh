#!/usr/bin/env bash
# run_all_benchmarks.sh — build and run the full benchmark sweep,
# then invoke the plotting script.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── Configuration ─────────────────────────────────────────────────────────────
T_VALUES="${T_VALUES:-64,256,1024,4096}"
LAMBDA="${LAMBDA:-2048}"
RESULTS_DIR="results"

echo "================================================================"
echo "  VDF Benchmark Suite"
echo "  T values : ${T_VALUES}"
echo "  λ        : ${LAMBDA} bits"
echo "================================================================"
echo

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[1/3] Building (release mode)…"
cargo build --release -p vdf-bench 2>&1 | tail -5
echo

# ── Run ───────────────────────────────────────────────────────────────────────
echo "[2/3] Running benchmarks…"
mkdir -p "${RESULTS_DIR}"
T_VALUES="${T_VALUES}" LAMBDA="${LAMBDA}" \
  cargo run --release -p vdf-bench 2>&1
echo

# ── Plot ──────────────────────────────────────────────────────────────────────
CSV="${RESULTS_DIR}/bench.csv"
if [[ -f "${CSV}" ]]; then
    echo "[3/3] Generating plots…"
    python3 scripts/plot_results.py "${CSV}"
else
    echo "[3/3] No CSV found at ${CSV} — skipping plots."
fi

echo
echo "Done.  Results in ${RESULTS_DIR}/"
