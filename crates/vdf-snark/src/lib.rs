//! Hash-chain VDF backed by an optional SP1 zkVM proof.
//!
//! Default feature `simulate` measures hash-chain sequentiality without
//! generating a real SNARK; enable `sp1` for production proof generation.

pub mod hash_chain;
pub mod prover;

use std::time::{Duration, Instant};

use vdf_core::{VDF, VDFOutput, VDFParams};

/// Hash-chain + SNARK VDF instance.
pub struct SnarkVDF {
    t: u64,
}

impl VDF for SnarkVDF {
    fn setup(params: &VDFParams) -> Self {
        SnarkVDF { t: params.t }
    }

    /// Evaluate `y = SHA256^T(x)`.
    fn eval(&self, x: &[u8]) -> (Vec<u8>, Duration) {
        let start = Instant::now();
        let y = hash_chain::hash_chain(x, self.t);
        let elapsed = start.elapsed();
        (y, elapsed)
    }

    /// Build (or simulate) a SNARK proof that `y = SHA256^T(x)`.
    fn prove(&self, x: &[u8], _y: &[u8]) -> (VDFOutput, Duration) {
        prover::prove(x, self.t)
    }

    /// Verify the SNARK proof (or re-run the chain in simulate mode).
    fn verify(&self, x: &[u8], out: &VDFOutput) -> bool {
        prover::verify(x, out, self.t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_pipeline() {
        let vdf = SnarkVDF::setup(&VDFParams { t: 100, lambda: 128 });
        let x = b"snark-integration-test";
        let (y, _) = vdf.eval(x);
        let (out, _) = vdf.prove(x, &y);
        assert!(vdf.verify(x, &out));
    }
}
