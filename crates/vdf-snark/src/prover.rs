//! SNARK prover interface for the hash-chain VDF.
//!
//! Two modes are compiled depending on the active Cargo feature:
//!
//! * **`simulate`** (default) — measures hash-chain time and returns an empty
//!   proof stub.  No zkVM toolchain required.
//! * **`sp1`** — drives the SP1 zkVM prover to generate a real
//!   Groth16 / PLONK proof over the guest program in `program/`.
//!
//! ## SP1 setup
//! ```bash
//! # 1. Install the SP1 toolchain
//! curl -L https://sp1.succinct.xyz | bash && sp1up
//!
//! # 2. Build the guest ELF
//! cd crates/vdf-snark/program && cargo prove build
//!
//! # 3. Set the path and run with real proving
//! export SNARK_ELF_PATH=crates/vdf-snark/program/elf/riscv32im-succinct-zkvm-elf
//! cargo run --release -p vdf-bench --features vdf-snark/sp1
//! ```

use std::time::{Duration, Instant};

use vdf_core::{VDFOutput};

use crate::hash_chain::hash_chain;

// ── Simulate mode (active when "sp1" feature is NOT enabled) ─────────────────

#[cfg(not(feature = "sp1"))]
/// Generate a simulated proof.
///
/// Runs the hash chain a second time (so the "prove" timing matches the
/// sequentiality cost) and writes `b"SIMULATED"` as the proof payload.
pub fn prove(x: &[u8], t: u64) -> (VDFOutput, Duration) {
    let y = hash_chain(x, t);
    let start = Instant::now();
    // Simulate prover work: re-run the hash chain (this mirrors what the
    // zkVM guest would execute, minus the SNARK overhead).
    let _ = hash_chain(x, t);
    let elapsed = start.elapsed();
    let out = VDFOutput {
        y,
        proof: b"SIMULATED".to_vec(),
    };
    (out, elapsed)
}

#[cfg(not(feature = "sp1"))]
/// Verify in simulate mode: re-run the hash chain.
pub fn verify(x: &[u8], out: &VDFOutput, t: u64) -> bool {
    out.proof == b"SIMULATED" && crate::hash_chain::verify_hash_chain(x, &out.y, t)
}

// ── SP1 mode ──────────────────────────────────────────────────────────────────

#[cfg(feature = "sp1")]
/// Generate a real SP1 proof over the hash-chain guest program.
///
/// The guest ELF path is read from the `SNARK_ELF_PATH` environment variable
/// (set it to the compiled RISC-V binary produced by `cargo prove build`).
pub fn prove(x: &[u8], t: u64) -> (VDFOutput, Duration) {
    use sp1_sdk::{ProverClient, SP1Stdin};

    let elf_path = std::env::var("SNARK_ELF_PATH")
        .expect("SNARK_ELF_PATH must be set when using the sp1 feature");
    let elf = std::fs::read(&elf_path)
        .unwrap_or_else(|_| panic!("Could not read SP1 ELF from {elf_path}"));

    let mut stdin = SP1Stdin::new();
    stdin.write(x);
    stdin.write(&t);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(&elf);

    let y = hash_chain(x, t);

    let start = Instant::now();
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("SP1 proving failed");
    let elapsed = start.elapsed();

    let proof_bytes = bincode::serialize(&proof).expect("proof serialisation failed");
    let out = VDFOutput { y, proof: proof_bytes };

    // Store the verification key alongside the proof (prepend its length).
    let vk_bytes = bincode::serialize(&vk).expect("vk serialisation failed");
    let mut full_proof = (vk_bytes.len() as u64).to_be_bytes().to_vec();
    full_proof.extend_from_slice(&vk_bytes);
    full_proof.extend_from_slice(&out.proof);

    (VDFOutput { y: out.y, proof: full_proof }, elapsed)
}

#[cfg(feature = "sp1")]
/// Verify an SP1 proof.
pub fn verify(x: &[u8], out: &VDFOutput, _t: u64) -> bool {
    use sp1_sdk::{ProverClient, SP1VerifyingKey, SP1ProofWithPublicValues};

    if out.proof.len() < 8 {
        return false;
    }
    let vk_len = u64::from_be_bytes(out.proof[..8].try_into().unwrap()) as usize;
    if out.proof.len() < 8 + vk_len {
        return false;
    }
    let vk: SP1VerifyingKey =
        bincode::deserialize(&out.proof[8..8 + vk_len]).ok().unwrap();
    let proof: SP1ProofWithPublicValues =
        bincode::deserialize(&out.proof[8 + vk_len..]).ok().unwrap();

    let client = ProverClient::new();
    client.verify(&proof, &vk).is_ok()
        && crate::hash_chain::verify_hash_chain(x, &out.y, _t)
}
