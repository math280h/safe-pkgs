//! Structured runtime metrics for lockfile audits and package evaluation.
//!
//! Collects per-package evaluation latency, cache hit/miss counts, and registry
//! error counts. [`Metrics`] is thread-safe via atomics and shared through an
//! [`Arc`]; [`MetricsSnapshot`] is the serializable schema emitted in tracing
//! summaries and exposed to callers.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Thread-safe counters for evaluation latency, cache outcomes, and errors.
///
/// Shared across concurrent evaluation tasks via [`Arc`]. All updates use
/// relaxed atomics since counters are independent and only read together in
/// [`Metrics::snapshot`].
#[derive(Debug, Default)]
pub struct Metrics {
    evaluations: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    registry_errors: AtomicU64,
    total_latency_micros: AtomicU64,
}

impl Metrics {
    /// Creates a new zeroed metrics collector wrapped in an [`Arc`].
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records a cache hit for a package evaluation.
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a cache miss for a package evaluation.
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a registry/check error encountered during evaluation.
    pub fn record_registry_error(&self) {
        self.registry_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one completed evaluation and its wall-clock latency.
    pub fn record_evaluation(&self, latency: Duration) {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        self.total_latency_micros
            .fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
    }

    /// Captures a consistent-enough point-in-time view with derived ratios.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let evaluations = self.evaluations.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);
        let registry_errors = self.registry_errors.load(Ordering::Relaxed);
        let total_latency_micros = self.total_latency_micros.load(Ordering::Relaxed);

        let cache_lookups = cache_hits + cache_misses;
        let cache_hit_ratio = ratio(cache_hits, cache_lookups);
        let registry_error_rate = ratio(registry_errors, evaluations);
        let avg_latency_ms = if evaluations == 0 {
            0.0
        } else {
            (total_latency_micros as f64 / evaluations as f64) / 1000.0
        };

        MetricsSnapshot {
            evaluations,
            cache_hits,
            cache_misses,
            cache_hit_ratio,
            registry_errors,
            registry_error_rate,
            avg_latency_ms,
        }
    }
}

/// Serializable point-in-time view of collected runtime metrics.
///
/// This is the stable metrics schema: it is emitted as a structured tracing
/// summary at the end of a lockfile audit and returned by service accessors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricsSnapshot {
    /// Total number of package evaluations performed.
    pub evaluations: u64,
    /// Number of evaluations served from cache.
    pub cache_hits: u64,
    /// Number of evaluations that missed the cache.
    pub cache_misses: u64,
    /// Cache hit ratio: hits / (hits + misses), 0.0 when no lookups occurred.
    pub cache_hit_ratio: f64,
    /// Number of registry/check errors encountered.
    pub registry_errors: u64,
    /// Registry error rate: errors / evaluations, 0.0 when no evaluations.
    pub registry_error_rate: f64,
    /// Average evaluation latency in milliseconds, 0.0 when no evaluations.
    pub avg_latency_ms: f64,
}

/// Computes `numerator / denominator` as f64, returning 0.0 when the
/// denominator is zero.
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_has_zero_derived_values() {
        let metrics = Metrics::new();
        let snap = metrics.snapshot();
        assert_eq!(snap.evaluations, 0);
        assert_eq!(snap.cache_hit_ratio, 0.0);
        assert_eq!(snap.registry_error_rate, 0.0);
        assert_eq!(snap.avg_latency_ms, 0.0);
    }

    #[test]
    fn cache_hit_ratio_is_computed() {
        let metrics = Metrics::new();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        let snap = metrics.snapshot();
        assert_eq!(snap.cache_hits, 3);
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hit_ratio, 0.75);
    }

    #[test]
    fn registry_error_rate_is_computed() {
        let metrics = Metrics::new();
        metrics.record_evaluation(Duration::from_millis(1));
        metrics.record_evaluation(Duration::from_millis(1));
        metrics.record_evaluation(Duration::from_millis(1));
        metrics.record_evaluation(Duration::from_millis(1));
        metrics.record_registry_error();

        let snap = metrics.snapshot();
        assert_eq!(snap.evaluations, 4);
        assert_eq!(snap.registry_errors, 1);
        assert_eq!(snap.registry_error_rate, 0.25);
    }

    #[test]
    fn avg_latency_ms_is_computed() {
        let metrics = Metrics::new();
        metrics.record_evaluation(Duration::from_millis(10));
        metrics.record_evaluation(Duration::from_millis(30));

        let snap = metrics.snapshot();
        assert_eq!(snap.evaluations, 2);
        assert_eq!(snap.avg_latency_ms, 20.0);
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        let metrics = Metrics::new();
        metrics.record_cache_miss();
        metrics.record_evaluation(Duration::from_millis(5));

        let snap = metrics.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize snapshot");
        let decoded: MetricsSnapshot = serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(snap, decoded);
    }
}
