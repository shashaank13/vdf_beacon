//! Non-interactive Wesolowski proof via Fiat–Shamir.
//!
//! ## Protocol (Wesolowski 2018/623, §4)
//!
//! Claim: `y = g^(2^T) mod N`
//!
//! 1. Evaluate `y = g^(2^T)` via `T` sequential squarings.
//! 2. **Prime challenge** `ℓ = Hprime(bin(g) ‖ bin(y))` — a ~128-bit prime
//!    derived from **both** `g` and `y` via Fiat–Shamir (as required by §4,
//!    Theorem 5 of the paper).
//! 3. **Proof**  `π = g^⌊2^T/ℓ⌋` — a **single** group element, computed via
//!    Algorithm 4 (on-the-fly long division, O(T) group ops).
//! 4. **Remainder** `r = 2^T mod ℓ`  (fast via modular exponentiation).
//! 5. **Verification**: `π^ℓ · g^r ≡ y  (mod N)`.
//!
//! ## Algorithm 4 — on-the-fly long division
//!
//! The quotient `q = ⌊2^T / ℓ⌋` is built bit-by-bit in a single forward loop
//! while simultaneously accumulating `π = g^q`:
//!
//! ```text
//! π ← 1,  r ← 1              // r tracks 2^i mod ℓ
//! for i = 0..T:
//!     b  ← ⌊2r / ℓ⌋          // next quotient bit (0 or 1)
//!     r  ← 2r mod ℓ
//!     π  ← π² · g^b          // left-to-right square-and-multiply
//! return π
//! ```
//!
//! After T iterations π = g^q.  The verifier reconstructs `ℓ` independently
//! using the same `Hprime(g, y)` oracle, computes `r = 2^T mod ℓ`, and checks
//! `π^ℓ · g^r ≡ y`.
//!
//! ## Complexity
//! * **Prover** – `T` squarings for eval + `O(T)` group ops for proof = `~2T` total.
//! * **Verifier** – `O(1)` — two modular exponentiations with exponents ≤ `ℓ`.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use vdf_core::{RsaGroup, biguint_to_bytes, bytes_to_biguint};

use crate::eval::repeated_square;

// ── Prover ───────────────────────────────────────────────────────────────────

/// Evaluate `y = g^(2^t)` and build a Wesolowski proof `π = g^⌊2^T/ℓ⌋`.
///
/// Implements the full paper construction (Wesolowski 2018/623, §4):
/// 1. Compute `y` via `t` sequential squarings (eval pass).
/// 2. Derive `ℓ = Hprime(g ‖ y)` — Fiat–Shamir commits to both inputs.
/// 3. Compute `π` via Algorithm 4 (on-the-fly long division, prove pass).
///
/// Returns `(y, π)`.
pub fn eval_and_prove(group: &RsaGroup, g: &BigUint, t: u64) -> (BigUint, BigUint) {
    // Step 1: y = g^(2^t)
    let y = repeated_square(group, g, t);

    // Step 2: ℓ = Hprime(g ‖ y)  — requires y, so must follow eval
    let l = prime_challenge(g, &y);

    // Step 3: π = g^⌊2^t/ℓ⌋ via Algorithm 4
    let pi = compute_proof(group, g, t, &l);

    (y, pi)
}

/// Build a Wesolowski proof `π = g^⌊2^T/ℓ⌋` for the claim `y = g^(2^T)`.
///
/// `y` is required to derive the Fiat–Shamir challenge `ℓ = Hprime(g ‖ y)`
/// per the paper (§4, Theorem 5).
pub fn prove(group: &RsaGroup, g: &BigUint, y: &BigUint, t: u64) -> BigUint {
    let l = prime_challenge(g, y);
    compute_proof(group, g, t, &l)
}

/// Compute `π = g^⌊2^t/ℓ⌋` using Algorithm 4 (on-the-fly long division).
///
/// Forward loop: `r` tracks `2^i mod ℓ`; at each step `b = ⌊2r/ℓ⌋ ∈ {0,1}`
/// is the next quotient bit, and `π ← π² · g^b` accumulates left-to-right.
///
/// After `t` iterations: `π = g^q` where `q = ⌊2^t/ℓ⌋`.
fn compute_proof(group: &RsaGroup, g: &BigUint, t: u64, l: &BigUint) -> BigUint {
    let mut pi = BigUint::one();
    let mut r = BigUint::one(); // r = 2^0 mod ℓ = 1

    for _ in 0..t {
        let two_r = &r * 2u32;
        let b = &two_r / l; // 0 or 1  (r < ℓ, so two_r < 2ℓ)
        r = two_r % l;

        pi = group.square(&pi);
        if !b.is_zero() {
            pi = group.mul(&pi, g);
        }
    }
    pi
}

/// Serialise the Wesolowski proof (one group element) to bytes.
pub fn encode_proof(pi: &BigUint) -> Vec<u8> {
    biguint_to_bytes(pi, 256)
}

/// Deserialise the Wesolowski proof from bytes.
pub fn decode_proof(bytes: &[u8]) -> Option<BigUint> {
    if bytes.len() != 256 {
        return None;
    }
    Some(bytes_to_biguint(bytes))
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// Verify: `π^ℓ · g^r ≡ y  (mod N)`  where  `r = 2^T mod ℓ`.
///
/// `ℓ` is reconstructed via `Hprime(g ‖ y)`, matching the proving step.
pub fn verify(group: &RsaGroup, g: &BigUint, y: &BigUint, t: u64, pi: &BigUint) -> bool {
    let l = prime_challenge(g, y);
    // r = 2^T mod ℓ  (cheap — ℓ is ~128-bit)
    let r = BigUint::from(2u32).modpow(&BigUint::from(t), &l);
    // lhs = π^ℓ · g^r mod N
    let lhs = group.mul(&group.pow(pi, &l), &group.pow(g, &r));
    lhs == *y
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Derive the ~128-bit prime challenge `ℓ = Hprime(g ‖ y)`.
///
/// Hashes `(g ‖ y)` with SHA-256, keeps the low 128 bits, forces odd,
/// then increments by 2 until a prime is found (Miller–Rabin, 20 rounds).
///
/// Binding `ℓ` to both `g` and `y` follows §4, Theorem 5 of Wesolowski
/// (2018/623): the soundness proof requires the challenge to commit to `y`.
fn prime_challenge(g: &BigUint, y: &BigUint) -> BigUint {
    let mut h = Sha256::new();
    h.update(g.to_bytes_be());
    h.update(y.to_bytes_be());
    let digest = h.finalize();
    let seed = BigUint::from_bytes_be(&digest[..16]); // 128-bit

    let two = BigUint::from(2u32);
    let mut candidate = if &seed % &two == BigUint::zero() {
        seed + BigUint::one()
    } else {
        seed
    };
    loop {
        if miller_rabin(&candidate, 20) {
            return candidate;
        }
        candidate += &two;
    }
}

/// Probabilistic primality test (Miller–Rabin, `k` rounds).
///
/// Uses deterministic witnesses `{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
/// 37}` for the first 12 rounds, giving a deterministic result for all
/// `n < 3.3 × 10^24`.  For 128-bit candidates (`n < 2^128`) the remaining
/// rounds use larger witnesses, giving a false-positive probability < 4^{-k}.
fn miller_rabin(n: &BigUint, k: u32) -> bool {
    let zero = BigUint::zero();
    let one = BigUint::one();
    let two = BigUint::from(2u32);

    if *n < two {
        return false;
    }
    if *n == two || *n == BigUint::from(3u32) {
        return true;
    }
    if n % &two == zero {
        return false;
    }

    // Write n-1 = 2^s · d  with d odd.
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while &d % &two == zero {
        d /= &two;
        s += 1;
    }

    let base_witnesses: &[u64] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
                                    41, 43, 47, 53, 59, 61, 67, 71];

    'outer: for &w in base_witnesses.iter().take(k as usize) {
        let a = BigUint::from(w);
        if a >= *n {
            continue;
        }
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..s - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vdf_core::RsaGroup;
    use crate::eval::repeated_square;

    fn run(t: u64) {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"wesolowski-prove-test");
        let y = repeated_square(&g, &x, t);
        let pi = prove(&g, &x, &y, t);
        assert!(verify(&g, &x, &y, t, &pi), "verify failed for t={t}");
    }

    #[test]
    fn prove_verify_t1()  { run(1);  }
    #[test]
    fn prove_verify_t4()  { run(4);  }
    #[test]
    fn prove_verify_t16() { run(16); }
    #[test]
    fn prove_verify_t32() { run(32); }

    #[test]
    fn eval_and_prove_consistent() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"eval-and-prove-test");
        let (y, pi) = eval_and_prove(&g, &x, 16);
        assert!(verify(&g, &x, &y, 16, &pi));
    }

    #[test]
    fn wrong_y_fails() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"wes-wrong-y");
        let y = repeated_square(&g, &x, 8);
        let pi = prove(&g, &x, &y, 8);
        let bad_y = repeated_square(&g, &x, 7);
        assert!(!verify(&g, &x, &bad_y, 8, &pi));
    }

    #[test]
    fn prime_challenge_is_prime() {
        let g = BigUint::from(42u32);
        let y = BigUint::from(1337u32);
        let p = prime_challenge(&g, &y);
        assert!(miller_rabin(&p, 20));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"encode-test");
        let y = repeated_square(&g, &x, 4);
        let pi = prove(&g, &x, &y, 4);
        let encoded = encode_proof(&pi);
        let decoded = decode_proof(&encoded).unwrap();
        assert_eq!(pi, decoded);
    }
}
