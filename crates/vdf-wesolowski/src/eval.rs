//! Repeated-squaring evaluation (identical to the Pietrzak crate).
//!
//! Kept in its own module so Wesolowski remains a self-contained crate
//! with no dependency on `vdf-pietrzak`.

use num_bigint::BigUint;
use vdf_core::RsaGroup;

/// Compute `x^(2^t) mod N` by iterating `t` modular squarings.
pub fn repeated_square(group: &RsaGroup, x: &BigUint, t: u64) -> BigUint {
    let mut y = x.clone();
    for _ in 0..t {
        y = group.square(&y);
    }
    y
}
