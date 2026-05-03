//! `vdf-core` — shared trait, types, and RSA group arithmetic.
//!
//! Every construction crate depends on this crate and implements [`VDF`].

use std::time::Duration;

use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};

// Re-export so construction crates only need this one dependency.
pub use num_bigint;
pub use num_traits;

// ── Parameters & output ──────────────────────────────────────────────────────

/// Parameters shared by all VDF constructions.
#[derive(Clone, Debug)]
pub struct VDFParams {
    /// Delay parameter: number of squarings / hash iterations.
    pub t: u64,
    /// Security parameter in bits (e.g. `2048` for the RSA group).
    pub lambda: usize,
}

/// The output of a VDF evaluation together with its proof.
#[derive(Clone, Debug, Default)]
pub struct VDFOutput {
    /// Output value `y` serialised as big-endian bytes.
    pub y: Vec<u8>,
    /// Serialised proof (construction-specific encoding).
    pub proof: Vec<u8>,
}

// ── Common trait ─────────────────────────────────────────────────────────────

/// Uniform interface implemented by every VDF construction.
///
/// The `eval` / `prove` split is intentional: it lets the bench harness
/// measure sequentiality and proving overhead independently even though, for
/// RSA-group constructions, the two phases overlap algorithmically.
pub trait VDF: Sized {
    /// Initialise the construction (group setup, parameter derivation, …).
    fn setup(params: &VDFParams) -> Self;

    /// Evaluate `y = VDF(x)` and return `(y, wall-clock eval time)`.
    fn eval(&self, x: &[u8]) -> (Vec<u8>, Duration);

    /// Build a proof that `y = VDF(x)` and return `(output+proof, prove time)`.
    ///
    /// `y` is the value previously returned by [`eval`][Self::eval].
    fn prove(&self, x: &[u8], y: &[u8]) -> (VDFOutput, Duration);

    /// Return `true` iff the proof inside `out` is valid for input `x`.
    fn verify(&self, x: &[u8], out: &VDFOutput) -> bool;
}

// ── RSA group ────────────────────────────────────────────────────────────────

/// RSA group `ℤ*_N` over a 2048-bit modulus.
///
/// The modulus is the RSA-2048 challenge number from the RSA Factoring
/// Challenge — no party knows its factorisation, which is the security
/// assumption underlying RSA-group VDFs.
///
/// Source: <https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048>
#[derive(Clone, Debug)]
pub struct RsaGroup {
    /// The modulus `N`.
    pub n: BigUint,
}

/// RSA-2048 challenge number (decimal).
const RSA_2048_N: &str = concat!(
    "2519590847565789349402718324004839857142928212620403202777713783604366202070",
    "7595556264018525880784406918290641249515082189298559149176184502808489120072",
    "8449926873928072877673597141834727026189637501497182469116507761337985909570",
    "0097330459748808428401797429100642458691817195118746121515172654632282216869",
    "9875491824224336372590851418654620435767984233871847744479207399342365848238",
    "2428119816381501067481045166037730605620161967625613384414360383390441495263",
    "4432190114657544454178424020924616515723350778707749817125772467962926386356",
    "3732899121548314381678998850404453640235273819513786365643912120103971228221",
    "120720357"
);

impl RsaGroup {
    /// Construct a group for security parameter `lambda`.
    ///
    /// # Panics
    /// Panics if `lambda != 2048` (only value currently supported).
    pub fn new(lambda: usize) -> Self {
        assert_eq!(lambda, 2048, "Only λ = 2048 is supported");
        let n = BigUint::parse_bytes(RSA_2048_N.as_bytes(), 10)
            .expect("RSA-2048 constant is malformed");
        debug_assert!(n.bits() >= 2047, "modulus is shorter than expected");
        RsaGroup { n }
    }

    /// Modular squaring: `x² mod N`.
    #[inline]
    pub fn square(&self, x: &BigUint) -> BigUint {
        x.modpow(&BigUint::from(2u32), &self.n)
    }

    /// Modular exponentiation: `x^e mod N`.
    #[inline]
    pub fn pow(&self, x: &BigUint, e: &BigUint) -> BigUint {
        x.modpow(e, &self.n)
    }

    /// Group multiplication: `(a · b) mod N`.
    #[inline]
    pub fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.n
    }

    /// Hash arbitrary bytes to a non-zero element of the group.
    ///
    /// Uses eight rounds of SHA-256 to produce 2048 bits before reduction.
    pub fn hash_to_element(&self, data: &[u8]) -> BigUint {
        let seed = Sha256::digest(data);
        let mut bytes = Vec::with_capacity(256);
        for ctr in 0u8..8 {
            let mut h = Sha256::new();
            h.update(seed);
            h.update([ctr]);
            bytes.extend_from_slice(&h.finalize());
        }
        let x = BigUint::from_bytes_be(&bytes) % &self.n;
        if x.is_zero() { BigUint::from(2u32) } else { x }
    }
}

// ── Serialisation helpers ────────────────────────────────────────────────────

/// Encode a `BigUint` as a fixed-width big-endian byte vector.
pub fn biguint_to_bytes(n: &BigUint, width: usize) -> Vec<u8> {
    let raw = n.to_bytes_be();
    let mut out = vec![0u8; width.saturating_sub(raw.len())];
    out.extend_from_slice(&raw);
    out
}

/// Decode a big-endian byte slice into a `BigUint`.
#[inline]
pub fn bytes_to_biguint(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_group_modulus_bit_length() {
        let g = RsaGroup::new(2048);
        let bits = g.n.bits();
        assert!(
            bits >= 2047 && bits <= 2048,
            "unexpected modulus bit length: {bits}"
        );
    }

    #[test]
    fn hash_to_element_is_nonzero() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"test input");
        assert!(!x.is_zero());
        assert!(x < g.n);
    }

    #[test]
    fn square_and_pow_agree() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"consistency check");
        assert_eq!(g.square(&x), g.pow(&x, &BigUint::from(2u32)));
    }
}
