//! Pietrzak VDF (2018/627) — recursive halving construction.
//!
//! * **Evaluation** `O(T)` squarings.
//! * **Proof size**  `O(log T)` group elements.
//! * **Proving**     `O(T)` squarings (naïve); `~3T/2` with checkpointing
//!   via [`PietrzakVDF::eval_and_prove`].
//! * **Verification** `O(log T)` modular exponentiations.
//!
//! The delay parameter `T` is rounded up to the nearest power of two so that
//! the recursive halving can always split evenly.  The effective delay is
//! reported in [`PietrzakVDF::t_eff`].

mod eval;
mod prove;

use std::time::{Duration, Instant};

use vdf_core::{
    bytes_to_biguint, biguint_to_bytes, RsaGroup, VDF, VDFOutput, VDFParams,
};
use eval::signed_abs;

/// Pietrzak VDF instance.
pub struct PietrzakVDF {
    group:  RsaGroup,
    /// Original requested delay (stored for informational purposes).
    #[allow(dead_code)]
    t:      u64,
    /// Effective delay (= `t.next_power_of_two()`).
    pub t_eff: u64,
}

impl VDF for PietrzakVDF {
    fn setup(params: &VDFParams) -> Self {
        let t_eff = params.t.next_power_of_two().max(2);
        PietrzakVDF {
            group: RsaGroup::new(params.lambda),
            t:     params.t,
            t_eff,
        }
    }

    /// Evaluate `y = x^(2^T_eff) mod N`.
    fn eval(&self, x: &[u8]) -> (Vec<u8>, Duration) {
        let x_elem = signed_abs(&self.group.hash_to_element(x), &self.group.n);
        let start = Instant::now();
        let y = eval::repeated_square(&self.group, &x_elem, self.t_eff);
        let elapsed = start.elapsed();
        (biguint_to_bytes(&y, 256), elapsed)
    }

    /// Build a recursive-halving proof for `y = x^(2^T_eff)`.
    fn prove(&self, x: &[u8], y: &[u8]) -> (VDFOutput, Duration) {
        let x_elem = signed_abs(&self.group.hash_to_element(x), &self.group.n);
        let y_elem = bytes_to_biguint(y);
        let start = Instant::now();
        let midpoints = prove::prove(&self.group, &x_elem, &y_elem, self.t_eff);
        let elapsed = start.elapsed();
        let out = VDFOutput {
            y: y.to_vec(),
            proof: prove::encode_proof(&midpoints),
        };
        (out, elapsed)
    }

    /// Verify that `proof` certifies `y = VDF(x)`.
    fn verify(&self, x: &[u8], out: &VDFOutput) -> bool {
        let x_elem = signed_abs(&self.group.hash_to_element(x), &self.group.n);
        let y_elem = bytes_to_biguint(&out.y);
        let Some(midpoints) = prove::decode_proof(&out.proof) else {
            return false;
        };
        prove::verify(&self.group, &x_elem, &y_elem, self.t_eff, &midpoints)
    }
}

impl PietrzakVDF {
    /// Evaluate `y = x^(2^T_eff)` **and** build a Pietrzak proof in a
    /// combined pass of `~3T/2` squarings.
    ///
    /// During the evaluation phase, `O(√T)` intermediate checkpoints of `x`
    /// are stored.  The first-level proof midpoint is then recovered from the
    /// nearest checkpoint in `O(√T)` squarings instead of `O(T/2)`.  Deeper
    /// recursion levels use naïve repeated squaring (their inputs are
    /// randomised and checkpoints no longer apply).
    ///
    /// Prefer this over calling [`eval`][Self::eval] followed by
    /// [`prove`][Self::prove] when both outputs are needed.
    pub fn eval_and_prove(&self, x: &[u8]) -> (VDFOutput, Duration) {
        let x_elem = signed_abs(&self.group.hash_to_element(x), &self.group.n);
        let start = Instant::now();
        let (y_elem, checkpoints, step) =
            eval::eval_checkpointed(&self.group, &x_elem, self.t_eff);
        let midpoints = prove::prove_with_checkpoints(
            &self.group,
            &x_elem,
            &y_elem,
            self.t_eff,
            &checkpoints,
            step,
        );
        let elapsed = start.elapsed();
        let out = VDFOutput {
            y: biguint_to_bytes(&y_elem, 256),
            proof: prove::encode_proof(&midpoints),
        };
        (out, elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_pipeline() {
        let vdf = PietrzakVDF::setup(&VDFParams { t: 8, lambda: 2048 });
        let x = b"integration-test";
        let (y, _eval_time) = vdf.eval(x);
        let (out, _prove_time) = vdf.prove(x, &y);
        assert!(vdf.verify(x, &out));
    }

    #[test]
    fn t_rounds_to_power_of_two() {
        let vdf = PietrzakVDF::setup(&VDFParams { t: 7, lambda: 2048 });
        assert_eq!(vdf.t_eff, 8);
    }

    #[test]
    fn eval_and_prove_matches_separate() {
        let vdf = PietrzakVDF::setup(&VDFParams { t: 8, lambda: 2048 });
        let x = b"combined-test";
        let (combined_out, _) = vdf.eval_and_prove(x);
        assert!(vdf.verify(x, &combined_out));
        // Output y must match independent eval.
        let (y, _) = vdf.eval(x);
        assert_eq!(combined_out.y, y);
    }
}
