//! Iterated SHA-256 hash chain: `y = SHA256^T(x)`.
//!
//! This is the *sequentiality kernel* used by the hash-based VDF construction.
//! Unlike the RSA-group constructions, the work per step is a cheap hash
//! rather than a modular squaring.

use sha2::{Digest, Sha256};

/// Compute `y = SHA256^t(x)` by applying SHA-256 `t` times.
pub fn hash_chain(x: &[u8], t: u64) -> Vec<u8> {
    if t == 0 {
        return x.to_vec();
    }
    let mut state: [u8; 32] = Sha256::digest(x).into();
    for _ in 1..t {
        state = Sha256::digest(state).into();
    }
    state.to_vec()
}

/// Verify `y = SHA256^t(x)` by re-running the chain.
///
/// This is the naïve `O(T)` verifier; a SNARK proof replaces it with
/// constant-time verification.
pub fn verify_hash_chain(x: &[u8], y: &[u8], t: u64) -> bool {
    hash_chain(x, t) == y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_iterations() {
        assert_eq!(hash_chain(b"abc", 0), b"abc");
    }

    #[test]
    fn one_iteration_matches_sha256() {
        use sha2::{Digest, Sha256};
        let x = b"hello";
        let expected: Vec<u8> = Sha256::digest(x).to_vec();
        assert_eq!(hash_chain(x, 1), expected);
    }

    #[test]
    fn verify_roundtrip() {
        let x = b"test-chain";
        let y = hash_chain(x, 50);
        assert!(verify_hash_chain(x, &y, 50));
        assert!(!verify_hash_chain(x, &y, 49));
    }
}
