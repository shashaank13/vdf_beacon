//! Wesolowski VDF (2018/627) — single-element proof construction.
//!
//! * **Evaluation** `O(T)` squarings.
//! * **Proof size**  `O(1)` — exactly one group element.
//! * **Proving**     `O(T)` group ops (binary long-division loop).
//! * **Verification** `O(1)` — two modular exponentiations with short exponents.

mod eval;
mod prove;

use std::time::{Duration, Instant};

use vdf_core::{
    bytes_to_biguint, biguint_to_bytes, RsaGroup, VDF, VDFOutput, VDFParams,
};

/// Wesolowski VDF instance.
pub struct WesolowskiVDF {
    group: RsaGroup,
    t:     u64,
}

impl VDF for WesolowskiVDF {
    fn setup(params: &VDFParams) -> Self {
        WesolowskiVDF {
            group: RsaGroup::new(params.lambda),
            t:     params.t,
        }
    }

    /// Evaluate `y = x^(2^T) mod N`.
    fn eval(&self, x: &[u8]) -> (Vec<u8>, Duration) {
        let x_elem = self.group.hash_to_element(x);
        let start = Instant::now();
        let y = eval::repeated_square(&self.group, &x_elem, self.t);
        let elapsed = start.elapsed();
        (biguint_to_bytes(&y, 256), elapsed)
    }

    /// Build a single-element Wesolowski proof `π = x^⌊2^T/ℓ⌋`.
    fn prove(&self, x: &[u8], y: &[u8]) -> (VDFOutput, Duration) {
        let x_elem = self.group.hash_to_element(x);
        let y_elem = bytes_to_biguint(y);
        let start = Instant::now();
        let pi = prove::prove(&self.group, &x_elem, &y_elem, self.t);
        let elapsed = start.elapsed();
        let out = VDFOutput {
            y: y.to_vec(),
            proof: prove::encode_proof(&pi),
        };
        (out, elapsed)
    }

    /// Verify `π^ℓ · x^r ≡ y (mod N)`.
    fn verify(&self, x: &[u8], out: &VDFOutput) -> bool {
        let x_elem = self.group.hash_to_element(x);
        let y_elem = bytes_to_biguint(&out.y);
        let Some(pi) = prove::decode_proof(&out.proof) else {
            return false;
        };
        prove::verify(&self.group, &x_elem, &y_elem, self.t, &pi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_pipeline() {
        let vdf = WesolowskiVDF::setup(&VDFParams { t: 16, lambda: 2048 });
        let x = b"wesolowski-integration";
        let (y, _) = vdf.eval(x);
        let (out, _) = vdf.prove(x, &y);
        assert!(vdf.verify(x, &out));
    }

    #[test]
    fn wrong_input_fails() {
        let vdf = WesolowskiVDF::setup(&VDFParams { t: 8, lambda: 2048 });
        let (y, _) = vdf.eval(b"correct-input");
        let (out, _) = vdf.prove(b"correct-input", &y);
        assert!(!vdf.verify(b"wrong-input", &out));
    }
}
