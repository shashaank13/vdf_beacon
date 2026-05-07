//! SP1 guest program: prove `y = H^T(x)` inside the zkVM.
//!
//! The host writes `(x: &[u8], t: u64, hash_selector: u8)` to stdin; the guest
//! reads them, runs the selected hash chain, and commits
//! `(x, t, hash_selector, y)` as public outputs so the
//! verifier can check the statement without rerunning the chain.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon_nostd::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};

fn poseidon_round(poseidon: &mut Poseidon<Fr>, input: &[u8]) -> [u8; 32] {
    let input_fe = Fr::from_be_bytes_mod_order(input);
    let output_fe = poseidon.hash(&[input_fe]).expect("Poseidon hashing failed");

    let mut out = [0u8; 32];
    let be = output_fe.into_bigint().to_bytes_be();
    let start = out.len().saturating_sub(be.len());
    out[start..].copy_from_slice(&be);
    out
}

#[inline]
fn sha256_round(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn main() {
    // Read inputs from the prover.
    let x: Vec<u8> = sp1_zkvm::io::read();
    let t: u64 = sp1_zkvm::io::read();
    let hash_selector: u8 = sp1_zkvm::io::read();

    // Execute the selected hash chain.
    let y = if t == 0 {
        x.clone()
    } else {
        match hash_selector {
            0 => {
                let mut state = sha256_round(&x);
                for _ in 1..t {
                    state = sha256_round(&state);
                }
                state.to_vec()
            }
            1 => {
                let mut poseidon = Poseidon::<Fr>::new_circom(1).expect("invalid Poseidon arity");
                let mut state = poseidon_round(&mut poseidon, &x);
                for _ in 1..t {
                    state = poseidon_round(&mut poseidon, &state);
                }
                state.to_vec()
            }
            _ => panic!("unsupported hash selector"),
        }
    };

    // Commit public outputs so the verifier can reconstruct the statement.
    sp1_zkvm::io::commit(&x);
    sp1_zkvm::io::commit(&t);
    sp1_zkvm::io::commit(&hash_selector);
    sp1_zkvm::io::commit(&y);
}
