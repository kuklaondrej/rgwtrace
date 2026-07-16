// SPDX-License-Identifier: GPL-2.0-only
//! Pure result-aggregation logic for the bench harness.
//!
//! Kept free of any BPF / libc dependency so it builds and unit-tests on every
//! platform (the harness proper is Linux-only). Everything here is deterministic
//! arithmetic over a slice of per-repetition `ns/call` samples.

use serde::Serialize;

/// Aggregate statistics over the timed repetitions of one phase.
///
/// `median` is the headline number (robust to a single slow rep from a
/// scheduler hiccup); `min`/`max` bracket the spread so a noisy run is visible
/// rather than hidden behind the median.
#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
pub struct Aggregate {
    pub reps: usize,
    pub median_ns: f64,
    pub min_ns: f64,
    pub max_ns: f64,
    pub mean_ns: f64,
    /// Peak-to-peak spread as a fraction of the median (`(max-min)/median`).
    /// A large value means the measurement is noisy and should not be trusted
    /// to the last nanosecond.
    pub spread_frac: f64,
}

/// Compute the aggregate of a set of per-rep `ns/call` samples.
///
/// Returns `None` for an empty input rather than inventing a zero, so a caller
/// cannot silently report a phase that never ran.
pub fn aggregate(samples: &[f64]) -> Option<Aggregate> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("bench samples are never NaN"));

    let reps = sorted.len();
    let median = median_sorted(&sorted);
    let min = sorted[0];
    let max = sorted[reps - 1];
    let mean = sorted.iter().sum::<f64>() / reps as f64;
    let spread_frac = if median > 0.0 {
        (max - min) / median
    } else {
        0.0
    };

    Some(Aggregate {
        reps,
        median_ns: median,
        min_ns: min,
        max_ns: max,
        mean_ns: mean,
        spread_frac,
    })
}

/// Median of an already-sorted slice (ascending). Even lengths average the two
/// central samples.
fn median_sorted(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// The derived cost of subtracting one phase's median from another's, floored at
/// zero. Used for `t_prog = real - trap` and `t_trap = trap - baseline`: a
/// (small) negative result is measurement noise, not a negative cost, so it is
/// clamped and flagged via `noisy`.
#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
pub struct Derived {
    /// `max(0, minuend - subtrahend)`.
    pub value_ns: f64,
    /// The raw, unclamped difference (may be negative under noise).
    pub raw_ns: f64,
    /// True when the raw difference was negative, i.e. the two phases were
    /// statistically indistinguishable and the floor kicked in.
    pub noisy: bool,
}

/// Subtract `subtrahend` from `minuend`, flooring at zero.
pub fn derive(minuend: f64, subtrahend: f64) -> Derived {
    let raw = minuend - subtrahend;
    Derived {
        value_ns: raw.max(0.0),
        raw_ns: raw,
        noisy: raw < 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "{a} !~= {b}");
    }

    #[test]
    fn empty_samples_have_no_aggregate() {
        assert!(aggregate(&[]).is_none());
    }

    #[test]
    fn odd_length_median_is_the_middle_sample() {
        // Deliberately unsorted input to prove the aggregator sorts first.
        let agg = aggregate(&[30.0, 10.0, 20.0]).expect("non-empty");
        approx(agg.median_ns, 20.0);
        approx(agg.min_ns, 10.0);
        approx(agg.max_ns, 30.0);
        approx(agg.mean_ns, 20.0);
        assert_eq!(agg.reps, 3);
    }

    #[test]
    fn even_length_median_averages_the_two_central_samples() {
        let agg = aggregate(&[10.0, 20.0, 30.0, 40.0]).expect("non-empty");
        approx(agg.median_ns, 25.0);
        approx(agg.spread_frac, (40.0 - 10.0) / 25.0);
    }

    #[test]
    fn single_sample_has_zero_spread() {
        let agg = aggregate(&[42.0]).expect("non-empty");
        approx(agg.median_ns, 42.0);
        approx(agg.spread_frac, 0.0);
    }

    #[test]
    fn derive_floors_a_negative_difference_and_flags_it() {
        let d = derive(5.0, 8.0);
        approx(d.value_ns, 0.0);
        approx(d.raw_ns, -3.0);
        assert!(d.noisy);
    }

    #[test]
    fn derive_passes_through_a_positive_difference() {
        let d = derive(120.0, 40.0);
        approx(d.value_ns, 80.0);
        approx(d.raw_ns, 80.0);
        assert!(!d.noisy);
    }
}
