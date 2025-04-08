//! Simple structured logging for auth service.
//!
//! Provides a single consistent format for log messages.

use log::{info, warn, error, debug};
use serde_json::json;
use chrono::Utc;

/// Simple structured logger for auth service
pub struct Log;

impl Log {
    /// Log an event with structured format
    pub fn event(
        level: &str,
        process: &str,
        event: &str,
        result: &str,
    ) {
        let log_data = json!({
            "service": "auth-service",
            "process": process,
            "event": event,
            "result": result,
            "timestamp": Utc::now().to_rfc3339(),
        });

        let log_str = log_data.to_string();
        
        match level {
            "DEBUG" => debug!("{}", log_str),
            "INFO" => info!("{}", log_str),
            "WARN" => warn!("{}", log_str),
            "ERROR" => error!("{}", log_str),
            _ => warn!("Unknown log level: {}", log_str),
        }
    }
    
    /// Log an event with DEBUG level for detailed diagnostics
    pub fn debug(process: &str, event: &str, result: &str) {
        Self::event("DEBUG", process, event, result);
    }
    
    /// Log an event with INFO level for normal operations
    pub fn info(process: &str, event: &str, result: &str) {
        Self::event("INFO", process, event, result);
    }
    
    /// Log an event with WARN level for concerning situations
    pub fn warn(process: &str, event: &str, result: &str) {
        Self::event("WARN", process, event, result);
    }
    
    /// Log an event with ERROR level for failures
    pub fn error(process: &str, event: &str, result: &str) {
        Self::event("ERROR", process, event, result);
    }
}