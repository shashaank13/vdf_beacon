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
//! export SNARK_ELF_PATH=target/elf-compilation/riscv32im-succinct-zkvm-elf/release/vdf-snark-program
//! cargo run --release -p vdf-bench --features vdf-snark/sp1
//! ```

use std::time::{Duration, Instant};

#[cfg(feature = "sp1")]
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "sp1")]
use sp1_sdk::{SP1ProvingKey, SP1VerifyingKey};

use vdf_core::{VDFOutput};
use crate::hash_chain::{hash_chain_with, verify_hash_chain_with, HashFunction};


#[cfg(feature = "sp1")]
type CachedSp1Keys = (String, SP1ProvingKey, SP1VerifyingKey);

#[cfg(feature = "sp1")]
static SP1_KEY_CACHE: OnceLock<Mutex<Option<CachedSp1Keys>>> = OnceLock::new();

#[cfg(feature = "sp1")]
fn cached_setup(
    client: &sp1_sdk::ProverClient,
    elf_path: &str,
    elf: &[u8],
) -> (SP1ProvingKey, SP1VerifyingKey, bool) {
    let cache = SP1_KEY_CACHE.get_or_init(|| Mutex::new(None));
    {
        let guard = cache.lock().expect("SP1 key cache mutex poisoned");
        if let Some((cached_path, pk, vk)) = guard.as_ref() {
            if cached_path == elf_path {
                return (pk.clone(), vk.clone(), true);
            }
        }
    }

    let (pk, vk) = client.setup(elf);
    let mut guard = cache.lock().expect("SP1 key cache mutex poisoned");
    *guard = Some((elf_path.to_string(), pk.clone(), vk.clone()));
    (pk, vk, false)
}

// ── Simulate mode (active when "sp1" feature is NOT enabled) ─────────────────

#[cfg(not(feature = "sp1"))]
/// Generate a simulated proof.
///
/// Runs the hash chain a second time (so the "prove" timing matches the
/// sequentiality cost) and writes `b"SIMULATED"` as the proof payload.
pub fn prove(x: &[u8], t: u64, hash_fn: HashFunction) -> (VDFOutput, Duration) {
    let y = hash_chain_with(hash_fn, x, t);
    let start = Instant::now();
    // Simulate prover work: re-run the hash chain (this mirrors what the
    // zkVM guest would execute, minus the SNARK overhead).
    let _ = hash_chain_with(hash_fn, x, t);
    let elapsed = start.elapsed();
    let out = VDFOutput {
        y,
        proof: b"SIMULATED".to_vec(),
    };
    (out, elapsed)
}

#[cfg(not(feature = "sp1"))]
/// Verify in simulate mode: re-run the hash chain.
pub fn verify(x: &[u8], out: &VDFOutput, t: u64, hash_fn: HashFunction) -> bool {
    out.proof == b"SIMULATED" && verify_hash_chain_with(hash_fn, x, &out.y, t)
}

// ── SP1 mode ──────────────────────────────────────────────────────────────────

#[cfg(feature = "sp1")]
/// Generate a real SP1 proof over the hash-chain guest program.
///
// The guest ELF path is read from the `SNARK_ELF_PATH` environment variable
/// (set it to the compiled RISC-V binary produced by `cargo prove build`).
pub fn prove(x: &[u8], t: u64, hash_fn: HashFunction) -> (VDFOutput, Duration) {
    use sp1_sdk::{ProverClient, SP1Stdin};

    let total_start = Instant::now();
    let elf_path = std::env::var("SNARK_ELF_PATH")
        .expect("SNARK_ELF_PATH must be set when using the sp1 feature");
    eprintln!("[sp1] loading guest ELF: {elf_path}");
    let load_start = Instant::now();
    let elf = std::fs::read(&elf_path)
        .unwrap_or_else(|_| panic!("Could not read SP1 ELF from {elf_path}"));
    eprintln!(
        "[sp1] loaded ELF ({} bytes) in {:.3}s",
        elf.len(),
        load_start.elapsed().as_secs_f64()
    );

    eprintln!("[sp1] preparing stdin");
    let mut stdin = SP1Stdin::new();
    stdin.write(&x.to_vec());
    stdin.write(&t);
    let hash_selector: u8 = match hash_fn {
        HashFunction::Sha256 => 0,
        HashFunction::Poseidon => 1,
    };
    stdin.write(&hash_selector);

    eprintln!("[sp1] initializing prover client");
    let client = ProverClient::new();
    eprintln!("[sp1] loading proving/verifying keys");
    let setup_start = Instant::now();
    let (pk, vk, cache_hit) = cached_setup(&client, &elf_path, &elf);
    eprintln!(
        "[sp1] {} in {:.3}s",
        if cache_hit { "key cache hit" } else { "setup complete" },
        setup_start.elapsed().as_secs_f64()
    );

    eprintln!("[sp1] proving started");
    let proof_mode = std::env::var("SP1_PROOF_MODE")
        .unwrap_or_else(|_| "compressed".to_string())
        .to_lowercase();
    eprintln!("[sp1] proof mode: {proof_mode}");

    let start = Instant::now();
    let prove_builder = client.prove(&pk, stdin);
    let proof = match proof_mode.as_str() {
        "core" => prove_builder
            .core()
            .run()
            .expect("SP1 proving failed in core mode"),
        "compressed" => prove_builder
            .compressed()
            .run()
            .expect("SP1 proving failed in compressed mode"),
        "plonk" => prove_builder
            .plonk()
            .run()
            .expect("SP1 proving failed in plonk mode"),
        "groth16" => prove_builder
            .groth16()
            .run()
            .expect("SP1 proving failed in groth16 mode"),
        _ => panic!(
            "Invalid SP1_PROOF_MODE='{proof_mode}'. Expected one of: core, compressed, plonk, groth16"
        ),
    };
    let elapsed = start.elapsed();
    eprintln!("[sp1] proving complete in {:.3}s", elapsed.as_secs_f64());

    // Guest commits (x, t, y) as public values; reuse y directly from the proof.
    let mut public_values = proof.public_values.clone();
    let proof_x: Vec<u8> = public_values.read();
    let proof_t: u64 = public_values.read();
    let proof_hash_selector: u8 = public_values.read();
    let y: Vec<u8> = public_values.read();
    if proof_x != x || proof_t != t || proof_hash_selector != hash_selector {
        panic!("SP1 public values mismatch between host inputs and guest outputs");
    }

    eprintln!("[sp1] serializing proof artifacts");
    let serialize_start = Instant::now();
    let proof_bytes = bincode::serialize(&proof).expect("proof serialisation failed");
    let out = VDFOutput { y, proof: proof_bytes };

    // Store the verification key alongside the proof (prepend its length).
    let vk_bytes = bincode::serialize(&vk).expect("vk serialisation failed");
    let mut full_proof = (vk_bytes.len() as u64).to_be_bytes().to_vec();
    full_proof.extend_from_slice(&vk_bytes);
    full_proof.extend_from_slice(&out.proof);

    eprintln!(
        "[sp1] serialization complete in {:.3}s",
        serialize_start.elapsed().as_secs_f64()
    );
    eprintln!("[sp1] total prove() time: {:.3}s", total_start.elapsed().as_secs_f64());

    (VDFOutput { y: out.y, proof: full_proof }, elapsed)
}

#[cfg(feature = "sp1")]
/// Verify an SP1 proof.
pub fn verify(x: &[u8], out: &VDFOutput, _t: u64, hash_fn: HashFunction) -> bool {
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

    // Bind host inputs/outputs to the guest-committed public values.
    let mut public_values = proof.public_values.clone();
    let proof_x: Vec<u8> = public_values.read();
    let proof_t: u64 = public_values.read();
    let proof_hash_selector: u8 = public_values.read();
    let proof_y: Vec<u8> = public_values.read();
    let expected_hash_selector: u8 = match hash_fn {
        HashFunction::Sha256 => 0,
        HashFunction::Poseidon => 1,
    };
    if proof_x != x
        || proof_t != _t
        || proof_hash_selector != expected_hash_selector
        || proof_y != out.y
    {
        return false;
    }

    let client = ProverClient::new();
    client.verify(&proof, &vk).is_ok()
}
