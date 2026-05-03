//! Non-interactive Pietrzak proof via Fiat–Shamir.
//!
//! ## Protocol (Pietrzak 2018/627, §3 — recursive halving)
//!
//! Claim: `y = x^(2^T) mod N`
//!
//! For `T = 1` (base case): proof is empty; verifier checks `x² = y`.
//!
//! For `T > 1` (recursive step):
//! 1. Prover computes the midpoint `μ = signed_abs(x^(2^⌊T/2⌋))`.
//! 2. Fiat–Shamir challenge: `r = H(x, y, T/2, μ)` — commits to the
//!    *half-interval length* as required by the paper's Figure 1.
//! 3. Derive new inputs (in QR⁺_N):
//!    `x' = signed_abs(x^r · μ)`,  `y' = signed_abs(μ^r · y)`.
//! 4. Recurse on `(x', y', ⌊T/2⌋)`.
//!
//! Proof = `[μ₁, μ₂, …, μ_{log T}]` — `O(log T)` group elements.
//!
//! ## QR⁺_N canonical form
//!
//! All group elements are kept in their *signed absolute value* representative
//! `signed_abs(x) = min(x, N − x)`.  This works in the quotient group
//! `QR⁺_N = QR_N / {±1}`, which is required for the soundness proof in §3 of
//! the paper to rule out the "negation" attack.
//!
//! ## Optimized prover (`prove_with_checkpoints`)
//!
//! During a combined eval+prove pass the evaluation phase stores `O(√T)`
//! checkpoints of the *original* input `x` at intervals of `step = ⌈√T⌉`.
//! The first-level midpoint `μ₁ = x^(2^{T/2})` is then read back from the
//! nearest checkpoint in `O(√T)` squarings instead of `O(T/2)`.  Deeper
//! recursion levels use modified inputs (`x' = x^r · μ`) for which no
//! checkpoints exist, so they fall back to repeated squaring.
//!
//! ## Complexity
//! * **Prover** – `O(T)` squarings (naïve); `~3T/2` (with checkpointing via
//!   [`prove_with_checkpoints`]).
//! * **Verifier** – `O(log T)` modular exponentiations.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use vdf_core::{RsaGroup, bytes_to_biguint, biguint_to_bytes};

use crate::eval::{repeated_square, square_from_checkpoint};

// ── QR⁺_N helper ─────────────────────────────────────────────────────────────

/// Map `x` to the canonical representative in `QR⁺_N = {min(x, N−x)}`.
///
/// Implements the "signed absolute value" from §3 of Pietrzak (2018/627):
/// elements of the quotient group `QR_N / {±1}` are uniquely represented by
/// the smaller of `x` and `N − x`.
#[inline]
fn signed_abs(x: &BigUint, n: &BigUint) -> BigUint {
    let neg = n - x;
    if x <= &neg { x.clone() } else { neg }
}

// ── Prover ───────────────────────────────────────────────────────────────────

/// Build a non-interactive Pietrzak proof for `y = x^(2^t)`.
///
/// Returns the ordered list of midpoints `[μ₁, …, μ_{⌊log₂ t⌋}]`.
///
/// `t` **must** be a power of two ≥ 2; the caller is responsible for
/// rounding up (see [`PietrzakVDF`][crate::PietrzakVDF]).
///
/// This is the naïve recursive implementation (`O(T)` squarings for the proof
/// alone).  For a faster combined eval+prove see [`prove_with_checkpoints`].
pub fn prove(group: &RsaGroup, x: &BigUint, y: &BigUint, t: u64) -> Vec<BigUint> {
    if t <= 1 {
        return vec![];
    }
    let half = t / 2;

    // μ = signed_abs(x^(2^{T/2})) — midpoint in QR⁺_N
    let mu = signed_abs(&repeated_square(group, x, half), &group.n);

    let r = fiat_shamir(x, y, half, &mu);

    // x' = signed_abs(x^r · μ),  y' = signed_abs(μ^r · y)
    let x_prime = signed_abs(&group.mul(&group.pow(x, &r), &mu), &group.n);
    let y_prime = signed_abs(&group.mul(&group.pow(&mu, &r), y), &group.n);

    let mut proof = vec![mu];
    proof.extend(prove(group, &x_prime, &y_prime, half));
    proof
}

/// Build a Pietrzak proof using pre-computed checkpoints of the original `x`.
///
/// The first-level midpoint `μ₁ = x^(2^{t/2})` is looked up from the
/// checkpoint table in `O(√T)` squarings.  All deeper recursion levels use
/// the naïve [`prove`] path because their inputs are modified by the
/// Fiat–Shamir randomisation and the original checkpoints no longer apply.
///
/// `checkpoints` and `step` are produced by
/// [`eval_checkpointed`][crate::eval::eval_checkpointed].
pub fn prove_with_checkpoints(
    group: &RsaGroup,
    x: &BigUint,
    y: &BigUint,
    t: u64,
    checkpoints: &[BigUint],
    step: u64,
) -> Vec<BigUint> {
    if t <= 1 {
        return vec![];
    }
    let half = t / 2;

    // Level 1: O(√T) squarings from the nearest checkpoint, then normalize.
    let mu = signed_abs(&square_from_checkpoint(group, checkpoints, step, half), &group.n);

    let r = fiat_shamir(x, y, half, &mu);
    let x_prime = signed_abs(&group.mul(&group.pow(x, &r), &mu), &group.n);
    let y_prime = signed_abs(&group.mul(&group.pow(&mu, &r), y), &group.n);

    let mut proof = vec![mu];
    // Deeper levels: x' is randomised — fall back to naïve recursion.
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
///
/// At each level the verifier reconstructs `r = H(x, y, T/2, μ)`, applies
/// the same QR⁺_N normalization as the prover, and recurses until the base
/// case `t = 1` where it checks `signed_abs(x²) = y`.
pub fn verify(group: &RsaGroup, x: &BigUint, y: &BigUint, t: u64, proof: &[BigUint]) -> bool {
    if t <= 1 {
        // Base case: signed_abs(x²) = y
        return signed_abs(&group.square(x), &group.n) == *y;
    }
    if proof.is_empty() {
        return false;
    }
    let half = t / 2;
    let mu = &proof[0];

    let r = fiat_shamir(x, y, half, mu);

    let x_prime = signed_abs(&group.mul(&group.pow(x, &r), mu), &group.n);
    let y_prime = signed_abs(&group.mul(&group.pow(mu, &r), y), &group.n);

    verify(group, &x_prime, &y_prime, half, &proof[1..])
}

// ── Fiat–Shamir ──────────────────────────────────────────────────────────────

/// Derive the 128-bit Fiat–Shamir challenge `r = H(x ‖ y ‖ half ‖ μ)`.
///
/// `half` is `T/2` — the half-interval length at the current recursion level,
/// matching the paper's Figure 1 which commits to the sub-interval being proved.
fn fiat_shamir(x: &BigUint, y: &BigUint, half: u64, mu: &BigUint) -> BigUint {
    let mut h = Sha256::new();
    h.update(x.to_bytes_be());
    h.update(y.to_bytes_be());
    h.update(half.to_be_bytes());
    h.update(mu.to_bytes_be());
    let digest = h.finalize();
    // 128-bit challenge — already < N (2048-bit), no further reduction needed.
    BigUint::from_bytes_be(&digest[..16])
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

    #[test]
    fn signed_abs_is_canonical() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"signed-abs-test");
        // x and N-x are negations; both must reduce to the same value.
        let neg_x = &g.n - &x;
        assert_eq!(signed_abs(&x, &g.n), signed_abs(&neg_x, &g.n));
        // Canonical value is ≤ N/2.
        let canonical = signed_abs(&x, &g.n);
        assert!(canonical <= &g.n / 2u32 + 1u32);
    }

    #[test]
    fn checkpoint_prove_matches_naive() {
        use crate::eval::eval_checkpointed;
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"checkpoint-vs-naive");
        let t = 8u64;
        let y = repeated_square(&g, &x, t);
        let naive_proof = prove(&g, &x, &y, t);
        let (_, checkpoints, step) = eval_checkpointed(&g, &x, t);
        let ckpt_proof = prove_with_checkpoints(&g, &x, &y, t, &checkpoints, step);
        assert_eq!(naive_proof, ckpt_proof, "checkpoint proof differs from naive");
        assert!(verify(&g, &x, &y, t, &naive_proof));
    }
}
