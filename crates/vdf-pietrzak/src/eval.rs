//! Repeated-squaring evaluation for the Pietrzak VDF.
//!
//! Elements are kept in their canonical **QR⁺_N** representative throughout:
//! for every pair {x, N−x} in QR_N we always store `min(x, N−x)`.
//! This canonicalisation is required by the Pietrzak soundness proof (§3 of
//! 2018/627) and is applied after every squaring via [`signed_abs`].

use num_bigint::BigUint;
use vdf_core::RsaGroup;

// ── QR⁺_N canonical form ─────────────────────────────────────────────────────

/// Map `x` to its canonical QR⁺_N representative: `min(x, N − x)`.
///
/// In the Pietrzak paper (2018/627, §3), the group is QR⁺_N — the set of
/// quadratic residues mod N with a fixed sign convention.  For each residue
/// pair {x, N−x} we pick the smaller element so that every group element has
/// a unique representation.  This must be applied after every group operation.
pub fn signed_abs(x: &BigUint, n: &BigUint) -> BigUint {
    let neg = n - x;
    if x <= &neg { x.clone() } else { neg }
}

// ── Evaluation ───────────────────────────────────────────────────────────────

/// Compute `x^(2^t) mod N` via `t` modular squarings, keeping each
/// intermediate value in its canonical QR⁺_N form.
///
/// Complexity: `O(T)` modular squarings, each on 2048-bit operands.
pub fn repeated_square(group: &RsaGroup, x: &BigUint, t: u64) -> BigUint {
    let mut y = x.clone();
    for _ in 0..t {
        y = signed_abs(&group.square(&y), &group.n);
    }
    y
}

/// Compute `y = x^(2^t)` while storing `O(√T)` intermediate checkpoints.
///
/// All stored values are in canonical QR⁺_N form.
///
/// Returns `(y, checkpoints, step)` where:
/// * `checkpoints[k] = x^(2^(k * step))` for `k = 0, 1, …`
/// * `step = ⌈√T⌉` (minimum 1)
///
/// This allows the first-level Pietrzak midpoint to be evaluated in
/// `O(√T)` squarings rather than `O(T/2)`.
pub fn eval_checkpointed(group: &RsaGroup, x: &BigUint, t: u64) -> (BigUint, Vec<BigUint>, u64) {
    let step = (t as f64).sqrt().ceil() as u64;
    let step = step.max(1);

    let mut current = x.clone();
    let mut checkpoints = vec![current.clone()]; // checkpoints[0] = x^(2^0)

    for i in 0..t {
        current = signed_abs(&group.square(&current), &group.n);
        if (i + 1) % step == 0 {
            checkpoints.push(current.clone());
        }
    }
    (current, checkpoints, step)
}

/// Reconstruct `x^(2^n)` from the checkpoint table produced by
/// [`eval_checkpointed`].
///
/// Finds the nearest checkpoint at or below position `n`, then applies at
/// most `step − 1` additional squarings (each maintaining QR⁺_N form).
/// Cost: `O(√T)` squarings.
pub fn square_from_checkpoint(
    group: &RsaGroup,
    checkpoints: &[BigUint],
    step: u64,
    n: u64,
) -> BigUint {
    let idx = (n / step) as usize;
    let mut val = checkpoints[idx].clone();
    for _ in 0..(n % step) {
        val = signed_abs(&group.square(&val), &group.n);
    }
    val
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vdf_core::RsaGroup;

    #[test]
    fn small_squaring() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"test");
        // Manual: apply signed_abs after each squaring to match repeated_square.
        let s1 = signed_abs(&g.square(&x), &g.n);
        let s2 = signed_abs(&g.square(&s1), &g.n);
        let s3 = signed_abs(&g.square(&s2), &g.n);
        assert_eq!(repeated_square(&g, &x, 3), s3);
    }

    #[test]
    fn zero_steps_returns_input() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"noop");
        assert_eq!(repeated_square(&g, &x, 0), x);
    }

    #[test]
    fn checkpoint_lookup_matches_repeated_square() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"checkpoint-test");
        let t = 16u64;
        let (y, checkpoints, step) = eval_checkpointed(&g, &x, t);
        assert_eq!(y, repeated_square(&g, &x, t));
        for &k in &[0u64, 1, 4, 7, 8, 15, 16] {
            let expected = repeated_square(&g, &x, k);
            let got = square_from_checkpoint(&g, &checkpoints, step, k);
            assert_eq!(got, expected, "mismatch at k={k}");
        }
    }

    #[test]
    fn signed_abs_is_canonical() {
        let g = RsaGroup::new(2048);
        let x = g.hash_to_element(b"canon");
        let s = signed_abs(&x, &g.n);
        // Applying signed_abs twice is idempotent.
        assert_eq!(s, signed_abs(&s, &g.n));
        // The canonical form is ≤ N/2.
        let half = &g.n / 2u32;
        assert!(s <= half);
    }
}
