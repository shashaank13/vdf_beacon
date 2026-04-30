//! Non-interactive Wesolowski proof via Fiat–Shamir.
//!
//! ## Protocol
//!
//! Claim: `y = x^(2^T) mod N`
//!
//! 1. **Prime challenge** `ℓ = next_prime(H(x, y, T))` — a ~128-bit prime
//!    derived deterministically from the statement.
//! 2. **Quotient** `q = ⌊2^T / ℓ⌋`  (computed iteratively in O(T)).
//! 3. **Proof**  `π = x^q mod N`  — a **single** group element.
//! 4. **Remainder** `r = 2^T mod ℓ`  (fast via modular exponentiation).
//! 5. **Verification**: `π^ℓ · x^r ≡ y  (mod N)`.
//!
//! ## Complexity
//! * **Prover** – `O(T)` squarings (the long-division loop).
//! * **Verifier** – `O(1)` — two modular exponentiations with exponents ≤ `ℓ`.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use vdf_core::{RsaGroup, biguint_to_bytes, bytes_to_biguint};

// ── Prover ───────────────────────────────────────────────────────────────────

/// Build a Wesolowski proof `π = x^⌊2^T/ℓ⌋` for the claim `y = x^(2^T)`.
pub fn prove(group: &RsaGroup, x: &BigUint, y: &BigUint, t: u64) -> BigUint {
    let l = prime_challenge(x, y, t);
    quotient_power(group, x, t, &l)
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

/// Verify: `π^ℓ · x^r ≡ y  (mod N)`  where  `r = 2^T mod ℓ`.
pub fn verify(group: &RsaGroup, x: &BigUint, y: &BigUint, t: u64, pi: &BigUint) -> bool {
    let l = prime_challenge(x, y, t);
    // r = 2^T mod l  (cheap — l is ~128-bit)
    let r = BigUint::from(2u32).modpow(&BigUint::from(t), &l);
    // lhs = π^l · x^r mod N
    let lhs = group.mul(&group.pow(pi, &l), &group.pow(x, &r));
    lhs == *y
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Compute `x^⌊2^T / l⌋ mod N` using binary long division.
///
/// At each of the `T+1` steps we process one bit of `2^T` (big-endian: the
/// leading "1" then `T` trailing "0"s).  The accumulator tracks `x^q` using
/// the square-and-multiply pattern, where `q` is built up bit-by-bit from the
/// long-division quotient.
fn quotient_power(group: &RsaGroup, x: &BigUint, t: u64, l: &BigUint) -> BigUint {
    // --- long division of 2^T by l ---
    // 2^T in binary: bit at position T is 1, all others 0.
    // We process T+1 bits from MSB (position T) to LSB (position 0).
    //
    // At each position we decide whether the current quotient bit is 0 or 1
    // (remainder >= l after shifting), and simultaneously build x^q with
    // standard square-and-multiply.

    let mut remainder = BigUint::zero();
    let mut pi = BigUint::one(); // π = x^q accumulated

    // Process bit T (value = 1)
    remainder = &remainder * 2u32 + 1u32;
    let bit = remainder >= *l;
    pi = group.square(&pi); // square first (MSB of q = 0 unless l=1)
    if bit {
        pi = group.mul(&pi, x);
        remainder -= l;
    }

    // Process bits T-1 .. 0 (all 0)
    for _ in 0..t {
        remainder = &remainder * 2u32;
        let bit = remainder >= *l;
        pi = group.square(&pi);
        if bit {
            pi = group.mul(&pi, x);
            remainder -= l;
        }
    }

    pi
}

/// Derive the ~128-bit prime challenge `ℓ` from the VDF statement.
///
/// We hash `(x ‖ y ‖ T)` with SHA-256, keep the low 128 bits, force odd,
/// then increment by 2 until we land on a prime (Miller–Rabin, ≤ 20 iters).
fn prime_challenge(x: &BigUint, y: &BigUint, t: u64) -> BigUint {
    let mut h = Sha256::new();
    h.update(x.to_bytes_be());
    h.update(y.to_bytes_be());
    h.update(t.to_be_bytes());
    let digest = h.finalize();
    let seed = BigUint::from_bytes_be(&digest[..16]); // 128-bit

    // Make it odd and search for next prime.
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

    // Deterministic witnesses valid up to ~3.3×10^24.
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
        use num_bigint::BigUint;
        let p = prime_challenge(&BigUint::from(42u32), &BigUint::from(99u32), 100);
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
