//! Iterated Poseidon hash chain: `y = Poseidon^T(x)`.
//!
//! This is the *sequentiality kernel* used by the hash-based VDF construction.
//! Unlike the RSA-group constructions, the work per step is a cheap hash
//! rather than a modular squaring.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon_nostd::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};

/// Hash primitive used in the sequential hash-chain kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFunction {
    Sha256,
    Poseidon,
}

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

/// Compute `y = H^t(x)` where `H` is chosen by `hash_fn`.
pub fn hash_chain_with(hash_fn: HashFunction, x: &[u8], t: u64) -> Vec<u8> {
    if t == 0 {
        return x.to_vec();
    }

    match hash_fn {
        HashFunction::Sha256 => {
            let mut state = sha256_round(x);
            for _ in 1..t {
                state = sha256_round(&state);
            }
            state.to_vec()
        }
        HashFunction::Poseidon => {
            let mut poseidon = Poseidon::<Fr>::new_circom(1).expect("invalid Poseidon arity");
            let mut state = poseidon_round(&mut poseidon, x);
            for _ in 1..t {
                state = poseidon_round(&mut poseidon, &state);
            }
            state.to_vec()
        }
    }
}

/// Compute `y = Poseidon^t(x)` by applying Poseidon `t` times.
pub fn hash_chain(x: &[u8], t: u64) -> Vec<u8> {
    hash_chain_with(HashFunction::Poseidon, x, t)
}

/// Verify `y = Poseidon^t(x)` by re-running the chain.
///
/// This is the naïve `O(T)` verifier; a SNARK proof replaces it with
/// constant-time verification.
pub fn verify_hash_chain(x: &[u8], y: &[u8], t: u64) -> bool {
    hash_chain(x, t) == y
}

/// Verify `y = H^t(x)` by re-running the selected chain.
pub fn verify_hash_chain_with(hash_fn: HashFunction, x: &[u8], y: &[u8], t: u64) -> bool {
    hash_chain_with(hash_fn, x, t) == y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_iterations() {
        assert_eq!(hash_chain(b"abc", 0), b"abc");
    }

    #[test]
    fn one_iteration_matches_poseidon() {
        use ark_bn254::Fr;
        use ark_ff::{BigInteger, PrimeField};
        use light_poseidon_nostd::{Poseidon, PoseidonHasher};

        let x = b"hello";
        let mut poseidon = Poseidon::<Fr>::new_circom(1).expect("invalid Poseidon arity");
        let output_fe = poseidon
            .hash(&[Fr::from_be_bytes_mod_order(x)])
            .expect("Poseidon hashing failed");
        let mut expected = [0u8; 32];
        let be = output_fe.into_bigint().to_bytes_be();
        let start = expected.len().saturating_sub(be.len());
        expected[start..].copy_from_slice(&be);
        assert_eq!(hash_chain(x, 1), expected);
    }

    #[test]
    fn verify_roundtrip() {
        let x = b"test-chain";
        let y = hash_chain(x, 50);
        assert!(verify_hash_chain(x, &y, 50));
        assert!(!verify_hash_chain(x, &y, 49));
    }

    #[test]
    fn sha256_roundtrip() {
        let x = b"sha-chain";
        let y = hash_chain_with(HashFunction::Sha256, x, 50);
        assert!(verify_hash_chain_with(HashFunction::Sha256, x, &y, 50));
        assert!(!verify_hash_chain_with(HashFunction::Sha256, x, &y, 49));
    }
}
