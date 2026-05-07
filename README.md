# VDF Benchmark

Benchmarks three Verifiable Delay Function constructions side-by-side:

| Crate | Construction | Reference |
|-------|-------------|-----------|
| `vdf-pietrzak`   | Recursive-halving proof (2018/623) | Pietrzak |
| `vdf-wesolowski` | Single-element proof   (2018/627) | Wesolowski |
| `vdf-snark`      | Iterated SHA-256 or Poseidon + zkVM proof | SP1/Jolt  |

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
| Prove            | O(T) group ops†  | O(T) group ops  | zkVM overhead (~10⁴×), hash-dependent |
| Proof size       | O(log T) elems   | O(1) — 1 elem   | ~100–300 KB           |
| Verify           | O(log T)         | O(1) — 2 mults  | SNARK verify (~ms)    |
| Trusted setup    | None             | None            | Backend-dependent     |

† Naive recursive implementation; optimised to O(√T) with checkpointing.

## Run In SP1 Mode

The guest program in `crates/vdf-snark/program/` runs inside SP1 zkVM.
That crate is excluded from the root workspace, so build it separately.

### 1) Build The SP1 Guest ELF

```bash
cd crates/vdf-snark/program
cargo prove build
```

Notes:
- Requires SP1 toolchain (`sp1up`).
- The guest uses an SP1-patched `sha2` dependency so SHA-256 runs through the
  SP1 precompile path.

### 2) Set SNARK_ELF_PATH To The ELF File (Not A Directory)

From repo root, point `SNARK_ELF_PATH` to the built binary file:

```bash
export SNARK_ELF_PATH=target/elf-compilation/riscv32im-succinct-zkvm-elf/release/vdf-snark-program
```

Quick validation:

```bash
ls -lh "$SNARK_ELF_PATH"
```

If this fails, rebuild the guest (step 1) and re-check the path.

### 3) Run Bench In SP1 Mode

```bash
cargo run --release -p vdf-bench --features vdf-snark/sp1
```

Optional quick smoke test:

```bash
T_VALUES=10 cargo run --release -p vdf-bench --features vdf-snark/sp1
```

### 4) Optional Proof Mode Selection

`vdf-snark` supports selecting SP1 proof type using `SP1_PROOF_MODE`:

```bash
SP1_PROOF_MODE=groth16 \
cargo run --release -p vdf-bench --features vdf-snark/sp1
```

Supported values:
- `core`
- `compressed` (default)
- `plonk`
- `groth16`

### ELF Handling Tips

- Keep `SNARK_ELF_PATH` as an absolute or repo-root-relative file path.
- Do not set `SNARK_ELF_PATH` to `.../riscv32im-succinct-zkvm-elf` (directory).
- Rebuild guest ELF after any change under `crates/vdf-snark/program/`.
- If multiple ELF targets exist, use the `riscv32im-succinct-zkvm-elf/release/vdf-snark-program`
  file unless you intentionally built another target.
- To locate candidate ELF files:

```bash
find target/elf-compilation -type f | rg 'vdf-snark-program|riscv32im-succinct-zkvm-elf'
```
