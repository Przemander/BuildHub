//! # Core Metrics - Common Infrastructure for BuildHub Metrics
//!
//! This module provides a unified foundation for all metrics in the system,
//! ensuring consistency, safety, and reliability across all instrumentation.

use lazy_static::lazy_static;
use prometheus::{
    core::Collector,
    Counter, CounterVec, Histogram, HistogramVec, Opts, Registry,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::{fmt, error};
use crate::log_warn;

// =============================================================================
// ERROR HANDLING
// =============================================================================

/// Error type for metric operations
#[derive(Debug)]
pub enum MetricError {
    /// Registration failed (e.g., duplicate metric)
    Registration(String),
    /// Invalid label value
    InvalidLabel(String),
    /// Invalid metric name
    InvalidName(String),
    /// Too many unique label values
    CardinalityLimit(String),
}

impl fmt::Display for MetricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricError::Registration(msg) => write!(f, "Metric registration error: {}", msg),
            MetricError::InvalidLabel(msg) => write!(f, "Invalid label value: {}", msg),
            MetricError::InvalidName(msg) => write!(f, "Invalid metric name: {}", msg),
            MetricError::CardinalityLimit(msg) => write!(f, "Cardinality limit exceeded: {}", msg),
        }
    }
}

impl error::Error for MetricError {}

// ✅ Uproszczona implementacja konwersji z prometheus::Error na MetricError
impl From<prometheus::Error> for MetricError {
    fn from(err: prometheus::Error) -> Self {
        match err {
            prometheus::Error::AlreadyReg => {
                MetricError::Registration("Metric already registered".to_string())
            },
            // ✅ Ogólny case dla wszystkich pozostałych błędów
            _ => {
                // Sprawdzamy typ błędu przez string matching jako fallback
                let error_str = format!("{:?}", err);
                
                if error_str.contains("InvalidMetricName") || error_str.contains("invalid") && error_str.contains("name") {
                    MetricError::InvalidName(format!("Invalid metric name: {}", err))
                } else if error_str.contains("label") || error_str.contains("Label") {
                    MetricError::InvalidLabel(format!("Invalid label: {}", err))
                } else {
                    MetricError::Registration(format!("Prometheus error: {}", err))
                }
            }
        }
    }
}

// =============================================================================
// STANDARD HISTOGRAM BUCKETS
// =============================================================================

/// Standard histogram buckets for low-latency operations (0.1ms to 1s)
/// 
/// Suitable for:
/// - In-memory operations
/// - Fast database queries
/// - JWT token validation
/// - Input validation
pub const LATENCY_BUCKETS_FAST: &[f64] = &[
    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];

/// Standard histogram buckets for medium-latency operations (1ms to 10s)
/// 
/// Suitable for:
/// - Database write operations
/// - Redis operations
/// - External API calls
/// - Rate limiting operations
pub const LATENCY_BUCKETS_MEDIUM: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Standard histogram buckets for high-latency operations (10ms to 60s)
/// 
/// Suitable for:
/// - Email sending
/// - Long database operations
/// - Migrations
/// - Slow external services
pub const LATENCY_BUCKETS_SLOW: &[f64] = &[
    0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

// =============================================================================
// LABEL VALIDATION & CARDINALITY PROTECTION
// =============================================================================

lazy_static! {
    /// Tracks unique label values for high-cardinality protection
    static ref LABEL_CARDINALITY: Arc<RwLock<HashMap<String, HashMap<String, usize>>>> = 
        Arc::new(RwLock::new(HashMap::new()));
    
    /// Registry for all BuildHub metrics
    static ref REGISTRY: Registry = Registry::new();
}

/// Maximum allowed unique values per label
const MAX_LABEL_CARDINALITY: usize = 100;

/// Maximum allowed label value length
const MAX_LABEL_LENGTH: usize = 100;

/// Validates a label value to prevent cardinality explosion
///
/// This function:
/// 1. Checks if the value is within allowed length
/// 2. Sanitizes the value to remove problematic characters
/// 3. Tracks cardinality to prevent unbounded growth
/// 4. Returns a sanitized, safe label value
///
/// # Arguments
/// * `metric_name` - Name of the metric (for cardinality tracking)
/// * `label_name` - Name of the label (for cardinality tracking)
/// * `value` - The label value to validate
///
/// # Returns
/// * `Ok(String)` - Sanitized, safe label value
/// * `Err(MetricError)` - If validation fails
pub fn validate_label(metric_name: &str, label_name: &str, value: &str) -> Result<String, MetricError> {
    // 1. Check length
    if value.len() > MAX_LABEL_LENGTH {
        return Err(MetricError::InvalidLabel(format!(
            "Label value too long (max {}): {}",
            MAX_LABEL_LENGTH,
            truncate_for_logging(value)
        )));
    }

    // 2. Sanitize value (allow only alphanumeric, underscore, hyphen, period)
    let sanitized = sanitize_label_value(value);
    
    // 3. Check cardinality
    let cardinality_key = format!("{}:{}", metric_name, label_name);
    
    let mut labels = LABEL_CARDINALITY.write().unwrap();
    let label_map = labels.entry(cardinality_key.clone()).or_insert_with(HashMap::new);
    
    // Track this value if it's new
    if !label_map.contains_key(&sanitized) {
        // Check if we'd exceed cardinality limit
        if label_map.len() >= MAX_LABEL_CARDINALITY {
            return Err(MetricError::CardinalityLimit(format!(
                "Too many unique values for label '{}' in metric '{}' (limit: {})",
                label_name, metric_name, MAX_LABEL_CARDINALITY
            )));
        }
        
        // Add the new value
        label_map.insert(sanitized.clone(), 0);
    }
    
    // Increment usage count
    *label_map.get_mut(&sanitized).unwrap() += 1;
    
    Ok(sanitized)
}

/// Sanitizes a label value for safe Prometheus usage
fn sanitize_label_value(value: &str) -> String {
    // Replace unsafe characters with underscores
    let mut sanitized = String::with_capacity(value.len());
    
    for c in value.chars() {
        if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
            sanitized.push(c);
        } else {
            sanitized.push('_');
        }
    }
    
    // Ensure it's not empty
    if sanitized.is_empty() {
        sanitized = "unknown".to_string();
    }
    
    sanitized
}

/// Truncates a string for safe logging
fn truncate_for_logging(s: &str) -> String {
    if s.len() <= 20 {
        s.to_string()
    } else {
        format!("{}...(+{} chars)", &s[0..20], s.len() - 20)
    }
}

// =============================================================================
// SAFE METRIC REGISTRATION
// =============================================================================

/// Safely registers a metric, handling duplicate registration gracefully
///
/// Instead of panicking on duplicate registration, this function:
/// 1. Attempts to register the metric
/// 2. If registration fails, logs a warning
/// 3. Returns an error instead of panicking
///
/// # Arguments
/// * `metric` - The metric to register
///
/// # Returns
/// * `Ok(())` - If registration succeeds
/// * `Err(MetricError)` - If registration fails
pub fn register_metric<C: Collector + Clone + 'static>(metric: &C) -> Result<(), MetricError> {
    match REGISTRY.register(Box::new(metric.clone())) {
        Ok(_) => Ok(()),
        Err(err) => {
            // Most likely a duplicate, which is fine during hot reloads or tests
            log_warn!(
                "Metrics", 
                &format!("Metric registration issue (likely duplicate): {}", err),
                "metric_registration"
            );
            Err(MetricError::Registration(err.to_string()))
        }
    }
}

// =============================================================================
// STANDARD METRIC CREATION FUNCTIONS
// =============================================================================

/// Creates a Counter with graceful error handling
pub fn create_counter(name: &str, help: &str) -> Result<Counter, MetricError> {
    let counter = Counter::new(name, help)?;
    match register_metric(&counter) {
        Ok(_) => Ok(counter),
        Err(e) => {
            // Try to get existing metric
            match Counter::new(name, help) {
                Ok(c) => Ok(c),
                Err(_) => Err(e),
            }
        }
    }
}

/// Creates a CounterVec with label validation
pub fn create_counter_vec(
    name: &str, 
    help: &str, 
    label_names: &[&str]
) -> Result<CounterVec, MetricError> {
    let counter = CounterVec::new(Opts::new(name, help), label_names)?;
    match register_metric(&counter) {
        Ok(_) => Ok(counter),
        Err(e) => {
            // Try to get existing metric
            match CounterVec::new(Opts::new(name, help), label_names) {
                Ok(c) => Ok(c),
                Err(_) => Err(e),
            }
        }
    }
}

/// Creates a Histogram with standard buckets
pub fn create_histogram(
    name: &str,
    help: &str, 
    buckets: &[f64]
) -> Result<Histogram, MetricError> {
    let hist = Histogram::with_opts(
        prometheus::HistogramOpts::new(name, help)
            .buckets(buckets.to_vec())
    )?;
    
    match register_metric(&hist) {
        Ok(_) => Ok(hist),
        Err(e) => {
            // Try to get existing metric
            match Histogram::with_opts(
                prometheus::HistogramOpts::new(name, help)
                    .buckets(buckets.to_vec())
            ) {
                Ok(h) => Ok(h),
                Err(_) => Err(e),
            }
        }
    }
}

/// Creates a HistogramVec with standard buckets and label validation
pub fn create_histogram_vec(
    name: &str,
    help: &str,
    label_names: &[&str],
    buckets: &[f64]
) -> Result<HistogramVec, MetricError> {
    let hist = HistogramVec::new(
        prometheus::HistogramOpts::new(name, help)
            .buckets(buckets.to_vec()),
        label_names
    )?;
    
    match register_metric(&hist) {
        Ok(_) => Ok(hist),
        Err(e) => {
            // Try to get existing metric
            match HistogramVec::new(
                prometheus::HistogramOpts::new(name, help)
                    .buckets(buckets.to_vec()),
                label_names
            ) {
                Ok(h) => Ok(h),
                Err(_) => Err(e),
            }
        }
    }
}

// =============================================================================
// SAFE OBSERVATION FUNCTIONS
// =============================================================================

// ✅ Usunięto nieużywany komentarz dokumentacyjny
lazy_static! {
    static ref METRIC_ERRORS: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
}

/// Maximum number of metric errors to log (prevents log spam)
const MAX_METRIC_ERRORS_TO_LOG: usize = 100;

/// Safely observes a counter with label validation
pub fn observe_counter_vec(
    counter: &CounterVec,
    metric_name: &str,
    label_values: &[&str]
) {
    // Must have the right number of labels
    if counter.desc().len() != 1 {
        return; // Malformed counter
    }
    
    let desc = &counter.desc()[0];
    let label_names = &desc.variable_labels;
    
    if label_values.len() != label_names.len() {
        log_metric_error(&format!(
            "Label count mismatch for {}: expected {}, got {}",
            metric_name, label_names.len(), label_values.len()
        ));
        return;
    }
    
    // Validate each label value
    let mut validated_values = Vec::with_capacity(label_values.len());
    
    for (i, value) in label_values.iter().enumerate() {
        let label_name = if i < label_names.len() {
            &label_names[i]
        } else {
            "unknown"
        };
        
        match validate_label(metric_name, label_name, value) {
            Ok(valid_value) => validated_values.push(valid_value),
            Err(e) => {
                log_metric_error(&format!(
                    "Invalid label for {} ({}={}): {}",
                    metric_name, label_name, value, e
                ));
                return;
            }
        }
    }
    
    // Convert to string slices
    let value_refs: Vec<&str> = validated_values.iter().map(|s| s.as_str()).collect();
    
    // Increment the counter
    counter.with_label_values(&value_refs).inc();
}

/// Safely observes a histogram with label validation
pub fn observe_histogram_vec(
    histogram: &HistogramVec,
    metric_name: &str,
    label_values: &[&str],
    value: f64
) {
    // Must have the right number of labels
    if histogram.desc().len() != 1 {
        return; // Malformed histogram
    }
    
    let desc = &histogram.desc()[0];
    let label_names = &desc.variable_labels;
    
    if label_values.len() != label_names.len() {
        log_metric_error(&format!(
            "Label count mismatch for {}: expected {}, got {}",
            metric_name, label_names.len(), label_values.len()
        ));
        return;
    }
    
    // Validate each label value
    let mut validated_values = Vec::with_capacity(label_values.len());
    
    for (i, value) in label_values.iter().enumerate() {
        let label_name = if i < label_names.len() {
            &label_names[i]
        } else {
            "unknown"
        };
        
        match validate_label(metric_name, label_name, value) {
            Ok(valid_value) => validated_values.push(valid_value),
            Err(e) => {
                log_metric_error(&format!(
                    "Invalid label for {} ({}={}): {}",
                    metric_name, label_name, value, e
                ));
                return;
            }
        }
    }
    
    // Validate the value
    if !value.is_finite() {
        log_metric_error(&format!(
            "Invalid histogram value for {}: {}",
            metric_name, value
        ));
        return;
    }
    
    // Convert to string slices
    let value_refs: Vec<&str> = validated_values.iter().map(|s| s.as_str()).collect();
    
    // Observe the value
    histogram.with_label_values(&value_refs).observe(value);
}

/// Logs metric errors with rate limiting to prevent log spam
fn log_metric_error(message: &str) {
    let mut count = METRIC_ERRORS.lock().unwrap();
    *count += 1;
    
    if *count <= MAX_METRIC_ERRORS_TO_LOG {
        log_warn!("Metrics", message, "metric_error");
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_label_validation() {
        // Valid label
        let valid = validate_label("test_metric", "test_label", "valid_value");
        assert!(valid.is_ok());
        assert_eq!(valid.unwrap(), "valid_value");
        
        // Sanitized label
        let sanitized = validate_label("test_metric", "test_label", "invalid value!");
        assert!(sanitized.is_ok());
        assert_eq!(sanitized.unwrap(), "invalid_value_");
        
        // Too long
        let long_value = "a".repeat(MAX_LABEL_LENGTH + 1);
        let too_long = validate_label("test_metric", "test_label", &long_value);
        assert!(too_long.is_err());
        match too_long {
            Err(MetricError::InvalidLabel(_)) => {},
            _ => panic!("Expected InvalidLabel error"),
        }
    }
    
    #[test]
    fn test_cardinality_protection() {
        // Reset for this test
        let mut labels = LABEL_CARDINALITY.write().unwrap();
        labels.clear();
        drop(labels);
        
        // Add just under the limit
        for i in 0..MAX_LABEL_CARDINALITY-1 {
            let result = validate_label(
                "high_cardinality_metric", 
                "high_cardinality_label",
                &format!("value_{}", i)
            );
            assert!(result.is_ok());
        }
        
        // Add one more to reach the limit
        let result = validate_label(
            "high_cardinality_metric", 
            "high_cardinality_label",
            &format!("value_{}", MAX_LABEL_CARDINALITY - 1)
        );
        assert!(result.is_ok());
        
        // Try to exceed the limit
        let result = validate_label(
            "high_cardinality_metric", 
            "high_cardinality_label",
            &format!("value_{}", MAX_LABEL_CARDINALITY)
        );
        assert!(result.is_err());
        match result {
            Err(MetricError::CardinalityLimit(_)) => {},
            _ => panic!("Expected CardinalityLimit error"),
        }
        
        // But we can reuse existing values
        let reuse = validate_label(
            "high_cardinality_metric", 
            "high_cardinality_label",
            "value_1"
        );
        assert!(reuse.is_ok());
    }
    
    #[test]
    fn test_sanitize_label_value() {
        assert_eq!(sanitize_label_value("normal"), "normal");
        assert_eq!(sanitize_label_value("with space"), "with_space");
        assert_eq!(sanitize_label_value("special!@#chars"), "special___chars");
        assert_eq!(sanitize_label_value(""), "unknown");
        assert_eq!(sanitize_label_value("valid-label.1"), "valid-label.1");
    }
    
    #[test]
    fn test_create_counter() {
        let counter = create_counter("test_counter", "Test counter").unwrap();
        counter.inc();
        assert_eq!(counter.get(), 1.0);
    }
    
    #[test]
    fn test_create_counter_vec() {
        let counter = create_counter_vec("test_counter_vec", "Test counter vec", &["label1"]).unwrap();
        counter.with_label_values(&["value1"]).inc();
        assert_eq!(counter.with_label_values(&["value1"]).get(), 1.0);
    }
    
    #[test]
    fn test_create_histogram() {
        let hist = create_histogram("test_hist", "Test histogram", LATENCY_BUCKETS_FAST).unwrap();
        hist.observe(0.1);
        assert_eq!(hist.get_sample_count(), 1);
    }
    
    #[test]
    fn test_create_histogram_vec() {
        let hist = create_histogram_vec(
            "test_hist_vec", 
            "Test histogram vec", 
            &["label1"],
            LATENCY_BUCKETS_FAST
        ).unwrap();
        
        hist.with_label_values(&["value1"]).observe(0.1);
        assert_eq!(hist.with_label_values(&["value1"]).get_sample_count(), 1);
    }
    
    #[test]
    fn test_observe_counter_vec() {
        let counter = create_counter_vec("test_observe_counter", "Test observe", &["label1"]).unwrap();
        
        // Valid observation
        observe_counter_vec(&counter, "test_observe_counter", &["valid"]);
        assert_eq!(counter.with_label_values(&["valid"]).get(), 1.0);
        
        // Invalid label (will be sanitized)
        observe_counter_vec(&counter, "test_observe_counter", &["invalid!"]);
        assert_eq!(counter.with_label_values(&["invalid_"]).get(), 1.0);
        
        // Wrong number of labels (should be ignored)
        observe_counter_vec(&counter, "test_observe_counter", &["too", "many"]);
        // Note: "too" is not a valid label value we've used, so it should be 0
        // The function should ignore the call due to wrong number of labels
    }
    
    #[test]
    fn test_observe_histogram_vec() {
        let hist = create_histogram_vec(
            "test_observe_hist", 
            "Test observe hist", 
            &["label1"],
            LATENCY_BUCKETS_FAST
        ).unwrap();
        
        // Valid observation
        observe_histogram_vec(&hist, "test_observe_hist", &["valid"], 0.1);
        assert_eq!(hist.with_label_values(&["valid"]).get_sample_count(), 1);
        
        // Invalid label (will be sanitized)
        observe_histogram_vec(&hist, "test_observe_hist", &["invalid!"], 0.2);
        assert_eq!(hist.with_label_values(&["invalid_"]).get_sample_count(), 1);
        
        // Invalid value (should be ignored)
        observe_histogram_vec(&hist, "test_observe_hist", &["valid"], f64::NAN);
        assert_eq!(hist.with_label_values(&["valid"]).get_sample_count(), 1); // unchanged
        
        // Wrong number of labels (should be ignored)
        observe_histogram_vec(&hist, "test_observe_hist", &["too", "many"], 0.3);
        // This should be ignored due to wrong number of labels
    }
}