//! Repeated-squaring evaluation: `y = x^(2^T) mod N`.

use num_bigint::BigUint;
use vdf_core::RsaGroup;

/// Compute `x^(2^t) mod N` by iterating `t` modular squarings.
///
/// Complexity: `O(T)` modular squarings, each on 2048-bit operands.
pub fn repeated_square(group: &RsaGroup, x: &BigUint, t: u64) -> BigUint {
    let mut y = x.clone();
    for _ in 0..t {
        y = group.square(&y);
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use vdf_core::RsaGroup;

    #[test]
    fn small_squaring() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"test");
        // x^(2^3) = ((x^2)^2)^2
        let manual = g.square(&g.square(&g.square(&x)));
        assert_eq!(repeated_square(&g, &x, 3), manual);
    }

    #[test]
    fn zero_steps_returns_input() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"noop");
        assert_eq!(repeated_square(&g, &x, 0), x);
    }
}
