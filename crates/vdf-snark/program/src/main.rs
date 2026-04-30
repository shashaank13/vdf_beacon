//! SP1 guest program: prove `y = SHA256^T(x)` inside the zkVM.
//!
//! The host writes `(x: &[u8], t: u64)` to stdin; the guest reads them,
//! runs the hash chain, and commits `(x, t, y)` as public outputs so the
//! verifier can check the statement without rerunning the chain.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    // Read inputs from the prover.
    let x: Vec<u8> = sp1_zkvm::io::read();
    let t: u64      = sp1_zkvm::io::read();

    // Execute the hash chain.  SP1's SHA-256 precompile accelerates this.
    let mut state: [u8; 32] = Sha256::digest(&x).into();
    for _ in 1..t {
        state = Sha256::digest(state).into();
    }
    let y = state.to_vec();

    // Commit public outputs so the verifier can reconstruct the statement.
    sp1_zkvm::io::commit(&x);
    sp1_zkvm::io::commit(&t);
    sp1_zkvm::io::commit(&y);
}
