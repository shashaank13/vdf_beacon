//! Hash-chain VDF backed by an optional SP1 zkVM proof.
//!
//! Default feature `simulate` measures hash-chain sequentiality without
//! generating a real SNARK; enable `sp1` for production proof generation.

pub mod hash_chain;
pub mod prover;

use std::time::{Duration, Instant};

use hash_chain::HashFunction;
use vdf_core::{VDF, VDFOutput, VDFParams};

/// Hash-chain + SNARK VDF instance.
pub struct SnarkVDF {
    t: u64,
    hash_fn: HashFunction,
}

impl SnarkVDF {
    fn new(t: u64, hash_fn: HashFunction) -> Self {
        Self { t, hash_fn }
    }
}

/// SHA-256 hash-chain SNARK VDF.
pub struct SnarkSha256VDF {
    inner: SnarkVDF,
}

/// Poseidon hash-chain SNARK VDF.
pub struct SnarkPoseidonVDF {
    inner: SnarkVDF,
}

impl VDF for SnarkVDF {
    fn setup(params: &VDFParams) -> Self {
        SnarkVDF::new(params.t, HashFunction::Poseidon)
    }

    /// Evaluate `y = Poseidon^T(x)`.
    fn eval(&self, x: &[u8]) -> (Vec<u8>, Duration) {
        let start = Instant::now();
        let y = hash_chain::hash_chain_with(self.hash_fn, x, self.t);
        let elapsed = start.elapsed();
        (y, elapsed)
    }

    /// Build (or simulate) a SNARK proof that `y = Poseidon^T(x)`.
    fn prove(&self, x: &[u8], _y: &[u8]) -> (VDFOutput, Duration) {
        prover::prove(x, self.t, self.hash_fn)
    }

    /// Verify the SNARK proof (or re-run the chain in simulate mode).
    fn verify(&self, x: &[u8], out: &VDFOutput) -> bool {
        prover::verify(x, out, self.t, self.hash_fn)
    }
}

impl VDF for SnarkSha256VDF {
    fn setup(params: &VDFParams) -> Self {
        Self {
            inner: SnarkVDF::new(params.t, HashFunction::Sha256),
        }
    }

    fn eval(&self, x: &[u8]) -> (Vec<u8>, Duration) {
        self.inner.eval(x)
    }

    fn prove(&self, x: &[u8], y: &[u8]) -> (VDFOutput, Duration) {
        self.inner.prove(x, y)
    }

    fn verify(&self, x: &[u8], out: &VDFOutput) -> bool {
        self.inner.verify(x, out)
    }
}

impl VDF for SnarkPoseidonVDF {
    fn setup(params: &VDFParams) -> Self {
        Self {
            inner: SnarkVDF::new(params.t, HashFunction::Poseidon),
        }
    }

    fn eval(&self, x: &[u8]) -> (Vec<u8>, Duration) {
        self.inner.eval(x)
    }

    fn prove(&self, x: &[u8], y: &[u8]) -> (VDFOutput, Duration) {
        self.inner.prove(x, y)
    }

    fn verify(&self, x: &[u8], out: &VDFOutput) -> bool {
        self.inner.verify(x, out)
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

    #[test]
    fn full_pipeline_sha256_variant() {
        let vdf = SnarkSha256VDF::setup(&VDFParams { t: 100, lambda: 128 });
        let x = b"snark-integration-test-sha";
        let (y, _) = vdf.eval(x);
        let (out, _) = vdf.prove(x, &y);
        assert!(vdf.verify(x, &out));
    }
}
