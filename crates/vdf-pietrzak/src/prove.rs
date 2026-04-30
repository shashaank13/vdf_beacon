//! Non-interactive Pietrzak proof via Fiat–Shamir.
//!
//! ## Protocol (recursive halving)
//!
//! Claim: `y = x^(2^T) mod N`
//!
//! For `T = 1` (base case): proof is empty; verifier checks `x² = y`.
//!
//! For `T > 1` (recursive step):
//! 1. Prover computes the midpoint `μ = x^(2^⌊T/2⌋)`.
//! 2. Fiat–Shamir challenge: `r = H(x, y, T, μ)` (128-bit).
//! 3. Derive new inputs: `x' = x^r · μ`,  `y' = μ^r · y`.
//! 4. Recurse on `(x', y', ⌊T/2⌋)`.
//!
//! Proof = `[μ₁, μ₂, …, μ_{log T}]` — `O(log T)` group elements.
//!
//! ## Complexity
//! * **Prover** – `O(T)` squarings (naive; can be reduced to `O(√T)` with
//!   checkpointing).
//! * **Verifier** – `O(log T)` modular exponentiations.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use vdf_core::{RsaGroup, bytes_to_biguint, biguint_to_bytes};

use crate::eval::repeated_square;

// ── Prover ───────────────────────────────────────────────────────────────────

/// Build a non-interactive Pietrzak proof for `y = x^(2^t)`.
///
/// Returns the ordered list of midpoints `[μ₁, …, μ_{⌊log₂ t⌋}]`.
///
/// `t` **must** be a power of two ≥ 2; the caller is responsible for
/// rounding up (see [`PietrzakVDF`][crate::PietrzakVDF]).
pub fn prove(group: &RsaGroup, x: &BigUint, y: &BigUint, t: u64) -> Vec<BigUint> {
    if t <= 1 {
        return vec![];
    }
    let half = t / 2;
    let mu = repeated_square(group, x, half);

    let r = fiat_shamir(x, y, t, &mu, &group.n);

    let x_r = group.pow(x, &r);
    let mu_r = group.pow(&mu, &r);
    let x_prime = group.mul(&x_r, &mu);
    let y_prime = group.mul(&mu_r, y);

    let mut proof = vec![mu];
    proof.extend(prove(group, &x_prime, &y_prime, half));
    proof
}

/// Serialise a Pietrzak proof (list of midpoints) to bytes.
///
/// Encoding: `[u64 count][256-byte element] …`  (big-endian, fixed width).
pub fn encode_proof(proof: &[BigUint]) -> Vec<u8> {
    let elem_width = 256usize; // 2048 bits
    let mut out = Vec::with_capacity(8 + proof.len() * elem_width);
    out.extend_from_slice(&(proof.len() as u64).to_be_bytes());
    for mu in proof {
        out.extend_from_slice(&biguint_to_bytes(mu, elem_width));
    }
    out
}

/// Deserialise a Pietrzak proof from bytes.
pub fn decode_proof(bytes: &[u8]) -> Option<Vec<BigUint>> {
    if bytes.len() < 8 {
        return None;
    }
    let count = u64::from_be_bytes(bytes[..8].try_into().ok()?) as usize;
    let elem_width = 256usize;
    if bytes.len() != 8 + count * elem_width {
        return None;
    }
    let elems = (0..count)
        .map(|i| {
            let start = 8 + i * elem_width;
            bytes_to_biguint(&bytes[start..start + elem_width])
        })
        .collect();
    Some(elems)
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// Verify a Pietrzak proof recursively.
///
/// Returns `true` iff the proof certifies `y = x^(2^t)`.
pub fn verify(group: &RsaGroup, x: &BigUint, y: &BigUint, t: u64, proof: &[BigUint]) -> bool {
    if t <= 1 {
        // Base case: x² = y
        return group.square(x) == *y;
    }
    if proof.is_empty() {
        return false;
    }
    let half = t / 2;
    let mu = &proof[0];

    let r = fiat_shamir(x, y, t, mu, &group.n);

    let x_r = group.pow(x, &r);
    let mu_r = group.pow(mu, &r);
    let x_prime = group.mul(&x_r, mu);
    let y_prime = group.mul(&mu_r, y);

    verify(group, &x_prime, &y_prime, half, &proof[1..])
}

// ── Fiat–Shamir ──────────────────────────────────────────────────────────────

/// Derive the 128-bit Fiat–Shamir challenge `r = H(x ‖ y ‖ T ‖ μ) mod n`.
fn fiat_shamir(x: &BigUint, y: &BigUint, t: u64, mu: &BigUint, n: &BigUint) -> BigUint {
    let mut h = Sha256::new();
    h.update(x.to_bytes_be());
    h.update(y.to_bytes_be());
    h.update(t.to_be_bytes());
    h.update(mu.to_bytes_be());
    let digest = h.finalize();
    // Use the first 16 bytes (128 bits) as the challenge.
    BigUint::from_bytes_be(&digest[..16]) % n
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vdf_core::RsaGroup;
    use crate::eval::repeated_square;

    fn run(t: u64) {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"pietrzak-prove-test");
        let y = repeated_square(&g, &x, t);
        let proof = prove(&g, &x, &y, t);
        let encoded = encode_proof(&proof);
        let decoded = decode_proof(&encoded).expect("decode failed");
        assert!(verify(&g, &x, &y, t, &decoded), "verify failed for t={t}");
    }

    #[test]
    fn prove_verify_t2()   { run(2); }
    #[test]
    fn prove_verify_t4()   { run(4); }
    #[test]
    fn prove_verify_t8()   { run(8); }
    #[test]
    fn prove_verify_t16()  { run(16); }
    #[test]
    fn prove_verify_t64()  { run(64); }

    #[test]
    fn wrong_y_fails() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"wrong-y");
        let y = repeated_square(&g, &x, 8);
        let proof = prove(&g, &x, &y, 8);
        let bad_y = repeated_square(&g, &x, 7); // off-by-one
        assert!(!verify(&g, &x, &bad_y, 8, &proof));
    }
}
