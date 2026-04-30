# VDF Benchmark

Benchmarks three Verifiable Delay Function constructions side-by-side:

| Crate | Construction | Reference |
|-------|-------------|-----------|
| `vdf-pietrzak`   | Recursive-halving proof (2018/623) | Pietrzak |
| `vdf-wesolowski` | Single-element proof   (2018/627) | Wesolowski |
| `vdf-snark`      | Iterated SHA-256 + zkVM proof      | SP1/Jolt  |

## Quick Start

```bash
# Build everything
cargo build --release

# Run the benchmark harness (writes results/bench.csv)
cargo run --release -p vdf-bench

# Plot results (requires Python + matplotlib/pandas)
python scripts/plot_results.py results/bench.csv
```

## Workspace Layout

```
vdf-benchmark/
├── Cargo.toml                    # workspace manifest
├── crates/
│   ├── vdf-core/                 # shared VDF trait + RSA group
│   ├── vdf-pietrzak/             # Construction 1 — recursive halving
│   ├── vdf-wesolowski/           # Construction 2 — single prime challenge
│   ├── vdf-snark/                # Construction 3 — hash chain + zkVM
│   │   └── program/              # SP1 guest program (RISC-V; separate build)
│   └── vdf-bench/                # benchmark harness + CSV output
└── scripts/
    ├── run_all_benchmarks.sh
    └── plot_results.py
```

## Theoretical Complexity

| Metric           | Pietrzak         | Wesolowski      | Hash + SNARK          |
|------------------|------------------|-----------------|-----------------------|
| Eval             | O(T) squarings   | O(T) squarings  | O(T) hashes           |
| Prove            | O(T) group ops†  | O(T) group ops  | zkVM overhead (~10⁴×) |
| Proof size       | O(log T) elems   | O(1) — 1 elem   | ~100–300 KB           |
| Verify           | O(log T)         | O(1) — 2 mults  | SNARK verify (~ms)    |
| Trusted setup    | None             | None            | Backend-dependent     |

† Naive recursive implementation; optimised to O(√T) with checkpointing.

## SP1 Guest Program

The `crates/vdf-snark/program/` directory contains the RISC-V guest that runs
inside SP1.  It is **excluded from the main workspace** and must be built
separately with the SP1 toolchain:

```bash
cd crates/vdf-snark/program
cargo prove build   # requires `sp1up` toolchain
```

Set the `SNARK_ELF_PATH` environment variable to the compiled ELF before
running the bench with the `sp1` feature:

```bash
SNARK_ELF_PATH=crates/vdf-snark/program/elf/riscv32im-succinct-zkvm-elf \
  cargo run --release -p vdf-bench --features vdf-snark/sp1
```
