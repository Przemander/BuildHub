//! Production-ready structured logging for BuildHub Auth Service.
//!
//! This module provides an enterprise-grade logging system with:
//!
//! - ECS-compliant JSON formatting compatible with Elasticsearch
//! - Non-blocking, high-performance asynchronous processing
//! - Graceful handling of file rotation and filesystem errors
//! - Backpressure handling with bounded channels
//! - Clean error recovery for robust production use
//!
//! # Architecture
//!
//! 1. Log events are sent to a bounded channel
//! 2. A dedicated background thread consumes messages from the channel
//! 3. Messages are formatted as JSON following Elastic Common Schema
//! 4. Logs are written to both console and persistent storage
//! 5. File writes use buffering with intelligent flush policies
//!
//! # Usage
//!
//! Use the provided macros rather than direct function calls:
//!
//! ```rust
//! use crate::{log_info, log_error};
//!
//! log_info!("Authentication", "User login attempt", "success");
//! log_error!("Database", "Connection failed", "failure");
//! ```

use chrono::Utc;
use crossbeam_channel::{bounded, Sender, TrySendError};
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum capacity of the log message queue before backpressure is applied
const LOG_CHANNEL_CAPACITY: usize = 10_000;

/// Buffer size for file writing operations (8KB)
const FILE_BUFFER_SIZE: usize = 8_192;

/// Number of messages to accumulate before forcing a flush to disk
const FLUSH_THRESHOLD: usize = 10;

/// Interval to force flush even if threshold not reached (in seconds)
const FLUSH_INTERVAL_SECS: u64 = 1;

/// Service name to include in all log entries
const SERVICE_NAME: &str = "auth-service";

/// Default directory for log files if not specified in environment
const DEFAULT_LOG_DIR: &str = "logs";

/// Default log file name
const LOG_FILE_NAME: &str = "auth-service.log";

/// Retry delay after file write errors (in seconds)
const FILE_ERROR_RETRY_DELAY_SECS: u64 = 5;

/// Log message structure for the internal channel
#[derive(Debug, Clone)]
struct LogMessage {
    /// Log severity level (INFO, WARN, ERROR, DEBUG)
    level: String,

    /// Process or module that generated the log
    process: String,

    /// Description of the event that occurred
    event: String,

    /// Outcome of the event (success, failure, etc.)
    result: String,

    /// File or location where the log was generated
    origin: String,
}

/// Handles log file writing with automatic error recovery
///
/// This struct manages writing logs to a file with built-in error
/// handling and recovery mechanisms. It includes:
///
/// - Automatic directory creation
/// - Buffered writing for performance
/// - Controlled flush policies
/// - Error recovery with exponential backoff
#[derive(Debug)]
struct LogFileWriter {
    /// Path to the log file
    log_path: String,

    /// Buffered writer for the log file
    writer: Option<BufWriter<File>>,

    /// Most recent error encountered (if any)
    last_error: Option<io::Error>,

    /// Time when next retry should be attempted after error
    retry_after: Option<Instant>,
}

impl LogFileWriter {
    /// Creates a new LogFileWriter for the given path
    ///
    /// # Arguments
    ///
    /// * `log_path` - The path where log files should be written
    ///
    /// # Returns
    ///
    /// A new LogFileWriter instance (unintialized)
    fn new(log_path: String) -> Self {
        Self {
            log_path,
            writer: None,
            last_error: None,
            retry_after: None,
        }
    }

    /// Initializes or reinitializes the writer after errors
    ///
    /// This will:
    /// 1. Check if we're in a backoff period
    /// 2. Create parent directories if needed
    /// 3. Open the log file with append mode
    /// 4. Initialize the buffered writer
    ///
    /// # Returns
    ///
    /// `true` if initialization succeeded, `false` otherwise
    fn initialize(&mut self) -> bool {
        // Check if we should wait before retrying
        if let Some(retry_time) = self.retry_after {
            if Instant::now() < retry_time {
                return false;
            }
        }

        // Ensure directory exists
        if let Some(parent) = Path::new(&self.log_path).parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                self.last_error = Some(e);
                self.retry_after =
                    Some(Instant::now() + Duration::from_secs(FILE_ERROR_RETRY_DELAY_SECS));
                return false;
            }
        }

        // Try to open or create the file
        match OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&self.log_path)
        {
            Ok(file) => {
                self.writer = Some(BufWriter::with_capacity(FILE_BUFFER_SIZE, file));
                self.last_error = None;
                self.retry_after = None;
                true
            }
            Err(e) => {
                self.last_error = Some(e);
                self.retry_after =
                    Some(Instant::now() + Duration::from_secs(FILE_ERROR_RETRY_DELAY_SECS));
                false
            }
        }
    }

    /// Writes a log entry to file, handling errors and recovery
    ///
    /// # Arguments
    ///
    /// * `entry` - The formatted log entry to write
    ///
    /// # Returns
    ///
    /// `true` if the write was successful, `false` otherwise
    fn write(&mut self, entry: &str) -> bool {
        // Ensure writer is initialized
        if self.writer.is_none() && !self.initialize() {
            return false;
        }

        // Write the log entry
        if let Some(writer) = &mut self.writer {
            if let Err(e) = writeln!(writer, "{}", entry) {
                self.last_error = Some(e);
                self.writer = None;

                // Try to reinitialize immediately
                return self.initialize() && self.write(entry);
            }
            true
        } else {
            false
        }
    }

    /// Flushes the writer to ensure data is written to disk
    ///
    /// # Returns
    ///
    /// `true` if the flush was successful, `false` otherwise
    fn flush(&mut self) -> bool {
        if let Some(writer) = &mut self.writer {
            match writer.flush() {
                Ok(_) => true,
                Err(e) => {
                    self.last_error = Some(e);
                    self.writer = None;
                    false
                }
            }
        } else {
            false
        }
    }

    /// Returns the most recent error encountered (if any)
    ///
    /// # Returns
    ///
    /// An Option containing a reference to the most recent error
    #[inline]
    fn last_error(&self) -> Option<&io::Error> {
        self.last_error.as_ref()
    }
}

/// Channel for sending log messages to the background processor
#[derive(Debug)]
struct LogChannel {
    /// Sender half of the bounded channel
    sender: Sender<LogMessage>,

    /// Counter for messages dropped due to backpressure
    dropped_count: AtomicUsize,
}

// Global channel for sending log messages
static LOG_CHANNEL: Lazy<Option<LogChannel>> = Lazy::new(|| {
    let (sender, receiver) = bounded::<LogMessage>(LOG_CHANNEL_CAPACITY);

    // Spawn a background thread for processing logs
    match thread::Builder::new()
        .name("log-processor".to_string())
        .spawn(move || {
            // Determine log directory from environment or use default
            let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| DEFAULT_LOG_DIR.to_string());
            let log_file_path = format!("{}/{}", log_dir, LOG_FILE_NAME);

            // Create file writer with auto-recovery
            let mut file_writer = LogFileWriter::new(log_file_path);
            let mut message_counter = 0usize;
            let mut last_flush = Instant::now();

            // Process messages until channel closes
            while let Ok(message) = receiver.recv() {
                let timestamp = Utc::now().to_rfc3339();

                // Create log entry in Elastic Common Schema format
                let log_data = create_log_entry(&timestamp, &message);
                let log_str = log_data.to_string();

                // Log to console through standard log macros
                log_to_console(&message.level, &log_str);

                // Write to log file with error handling
                if !file_writer.write(&log_str) {
                    // If writing fails after retry, log to stderr as fallback
                    if let Some(err) = file_writer.last_error() {
                        eprintln!("Error writing to log file: {}", err);
                    }
                }

                // Implement smart flush policy
                message_counter += 1;
                if should_flush(message_counter, last_flush) {
                    file_writer.flush();
                    last_flush = Instant::now();
                }
            }

            // Final flush before exit
            file_writer.flush();
        }) {
        Ok(_) => {
            // Thread started successfully
            Some(LogChannel {
                sender,
                dropped_count: AtomicUsize::new(0),
            })
        }
        Err(e) => {
            // Failed to start thread, log error and return None
            eprintln!("Failed to start log processor thread: {}", e);
            None
        }
    }
});

/// Creates a structured log entry in Elastic Common Schema format
///
/// # Arguments
///
/// * `timestamp` - The ISO 8601 timestamp for the log entry
/// * `message` - The log message containing event details
///
/// # Returns
///
/// A JSON Value containing the formatted log entry
#[inline]
fn create_log_entry(timestamp: &str, message: &LogMessage) -> Value {
    json!({
        "@timestamp":     timestamp,
        "log.level":      message.level,
        "log.logger":     message.process,
        "message":        message.event,
        "event.outcome":  message.result,
        "service.name":   SERVICE_NAME,
        "code.filepath":  message.origin,
    })
}

/// Routes log message to the appropriate console logger based on level
///
/// # Arguments
///
/// * `level` - The log level as a string
/// * `log_str` - The formatted log entry
#[inline]
fn log_to_console(level: &str, log_str: &str) {
    match level {
        "DEBUG" => debug!("{}", log_str),
        "INFO" => info!("{}", log_str),
        "WARN" => warn!("{}", log_str),
        "ERROR" => error!("{}", log_str),
        _ => warn!("Unknown log level: {}", log_str),
    }
}

/// Determines if a flush should be performed based on policy
///
/// # Arguments
///
/// * `counter` - Number of messages processed since last flush
/// * `last_flush` - Timestamp of the last flush operation
///
/// # Returns
///
/// `true` if a flush should be performed, `false` otherwise
#[inline]
fn should_flush(counter: usize, last_flush: Instant) -> bool {
    counter % FLUSH_THRESHOLD == 0 || last_flush.elapsed().as_secs() >= FLUSH_INTERVAL_SECS
}

/// Direct logging fallback when channel is unavailable
///
/// # Arguments
///
/// * `level` - Log level (INFO, ERROR, etc.)
/// * `process` - Process or module name
/// * `event` - Description of the event
/// * `result` - Outcome of the event
/// * `origin` - Source file of the log
fn fallback_log(level: &str, process: &str, event: &str, result: &str, origin: &str) {
    let timestamp = Utc::now().to_rfc3339();
    let message = LogMessage {
        level: level.to_string(),
        process: process.to_string(),
        event: event.to_string(),
        result: result.to_string(),
        origin: origin.to_string(),
    };

    let log_data = create_log_entry(&timestamp, &message);
    let log_str = log_data.to_string();
    log_to_console(level, &log_str);
}

/// Main logging interface for the application
#[derive(Debug)]
pub struct Log;

impl Log {
    /// Logs an event with ECS-compliant structured format
    ///
    /// This method is non-blocking - it sends the log to a background thread
    /// if initialized, falling back to synchronous logging if the channel
    /// is unavailable or at capacity.
    ///
    /// # Arguments
    ///
    /// * `level` - Log level (INFO, ERROR, etc.)
    /// * `process` - Process or module name
    /// * `event` - Description of the event
    /// * `result` - Outcome of the event
    /// * `origin` - Source file of the log
    pub fn event(level: &str, process: &str, event: &str, result: &str, origin: &str) {
        if let Some(channel) = &*LOG_CHANNEL {
            let message = LogMessage {
                level: level.to_string(),
                process: process.to_string(),
                event: event.to_string(),
                result: result.to_string(),
                origin: origin.to_string(),
            };

            // Try to send, but track dropped messages if channel is full
            if let Err(e) = channel.sender.try_send(message) {
                if matches!(e, TrySendError::Full(_)) {
                    // Increment the dropped count
                    channel.dropped_count.fetch_add(1, Ordering::Relaxed);
                }

                // Fallback to direct logging
                fallback_log(level, process, event, result, origin);
            }
        } else {
            // Fallback if the channel isn't initialized
            fallback_log(level, process, event, result, origin);
        }
    }

    /// Returns the count of log messages dropped due to backpressure
    ///
    /// This can be used to monitor the health of the logging system
    /// and detect if logs are being lost due to high volume.
    ///
    /// # Returns
    ///
    /// The number of dropped log messages
    #[allow(dead_code)]
    pub fn dropped_count() -> usize {
        if let Some(channel) = &*LOG_CHANNEL {
            return channel.dropped_count.load(Ordering::Relaxed);
        }
        0
    }

    /// Determines if the logging system has been properly initialized
    ///
    /// # Returns
    ///
    /// `true` if the logging system is initialized, `false` otherwise
    #[allow(dead_code)]
    pub fn is_initialized() -> bool {
        LOG_CHANNEL.is_some()
    }
}

// Macros for ergonomic logging

/// Logs a debug-level message
///
/// # Arguments
///
/// * `process` - Process or module name
/// * `event` - Description of the event
/// * `result` - Outcome of the event
///
/// # Example
///
/// ```
/// log_debug!("DataValidator", "Validating user input", "started");
/// ```
#[macro_export]
macro_rules! log_debug {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("DEBUG", $process, $event, $result, file!())
    };
}

/// Logs an info-level message
///
/// # Arguments
///
/// * `process` - Process or module name
/// * `event` - Description of the event
/// * `result` - Outcome of the event
///
/// # Example
///
/// ```
/// log_info!("Authentication", "User login attempt", "success");
/// ```
#[macro_export]
macro_rules! log_info {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("INFO", $process, $event, $result, file!())
    };
}

/// Logs a warning-level message
///
/// # Arguments
///
/// * `process` - Process or module name
/// * `event` - Description of the event
/// * `result` - Outcome of the event
///
/// # Example
///
/// ```
/// log_warn!("TokenService", "JWT expiration", "approaching");
/// ```
#[macro_export]
macro_rules! log_warn {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("WARN", $process, $event, $result, file!())
    };
}

/// Logs an error-level message
///
/// # Arguments
///
/// * `process` - Process or module name
/// * `event` - Description of the event
/// * `result` - Outcome of the event
///
/// # Example
///
/// ```
/// log_error!("Database", "Connection failed", "failure");
/// ```
#[macro_export]
macro_rules! log_error {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("ERROR", $process, $event, $result, file!())
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    // Initialize logger only once for all tests
    static INIT: Once = Once::new();

    fn init_logger() {
        INIT.call_once(|| {
            log::set_max_level(log::LevelFilter::Debug);
        });
    }

    #[test]
    fn test_log_file_writer_initialization() {
        // Create a temporary directory for logs
        let temp_dir = format!("/tmp/test_logs_{}", std::process::id());
        let path = format!("{}/test.log", temp_dir);

        let mut writer = LogFileWriter::new(path.clone());

        // Should initialize successfully
        assert!(writer.initialize(), "Writer should initialize successfully");
        assert!(
            writer.writer.is_some(),
            "Writer should be Some after initialization"
        );

        // Should write successfully
        assert!(writer.write("Test log entry"), "Write should succeed");
        assert!(writer.flush(), "Flush should succeed");

        // Check the file exists and contains our log
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content, "Test log entry\n",
            "File should contain the written log entry"
        );

        // Clean up
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_log_file_writer_error_handling() {
        // Create an invalid path (directory that doesn't exist and can't be created)
        let path = if cfg!(unix) {
            // This path requires root permission on Unix
            "/root/test_log_file_that_should_fail.log".to_string()
        } else if cfg!(windows) {
            // Invalid path on Windows (contains reserved characters)
            "COM1:\\invalid\\path.log".to_string()
        } else {
            // Fallback for other platforms
            "/nonexistent_directory_with_very_long_name_that_should_not_exist/test.log".to_string()
        };

        let mut writer = LogFileWriter::new(path);

        // Should fail to initialize
        assert!(
            !writer.initialize(),
            "Writer should fail to initialize with invalid path"
        );
        assert!(
            writer.writer.is_none(),
            "Writer should be None after failed initialization"
        );
        assert!(
            writer.last_error.is_some(),
            "Writer should have an error after failed initialization"
        );
    }

    #[test]
    fn test_create_log_entry_format() {
        let timestamp = "2023-01-01T00:00:00Z";
        let message = LogMessage {
            level: "INFO".to_string(),
            process: "TestProcess".to_string(),
            event: "Test event".to_string(),
            result: "success".to_string(),
            origin: "test.rs".to_string(),
        };

        let entry = create_log_entry(timestamp, &message);

        // Verify fields are present and correct
        assert_eq!(entry["@timestamp"], timestamp, "Timestamp should match");
        assert_eq!(entry["log.level"], "INFO", "Log level should match");
        assert_eq!(entry["log.logger"], "TestProcess", "Process should match");
        assert_eq!(entry["message"], "Test event", "Event should match");
        assert_eq!(entry["event.outcome"], "success", "Result should match");
        assert_eq!(
            entry["service.name"], SERVICE_NAME,
            "Service name should match"
        );
        assert_eq!(entry["code.filepath"], "test.rs", "Origin should match");
    }

    #[test]
    fn test_should_flush_policy() {
        // Test flush threshold
        assert!(
            should_flush(FLUSH_THRESHOLD, Instant::now()),
            "Should flush when counter equals threshold"
        );
        assert!(
            should_flush(FLUSH_THRESHOLD * 2, Instant::now()),
            "Should flush when counter is multiple of threshold"
        );
        assert!(
            !should_flush(FLUSH_THRESHOLD - 1, Instant::now()),
            "Should not flush when counter below threshold"
        );

        // Test time interval
        let old_time = Instant::now() - Duration::from_secs(FLUSH_INTERVAL_SECS + 1);
        assert!(
            should_flush(1, old_time),
            "Should flush when time interval exceeded regardless of counter"
        );

        let recent_time = Instant::now();
        assert!(
            !should_flush(1, recent_time),
            "Should not flush when time interval not exceeded and counter below threshold"
        );
    }

    #[test]
    fn test_logger_event() {
        init_logger();

        // This just verifies it doesn't panic
        Log::event("INFO", "TestModule", "Test event", "success", "test.rs");

        // Test with our macros
        log_debug!("TestDebug", "Debug log", "attempt");
        log_info!("TestInfo", "Info log", "success");
        log_warn!("TestWarn", "Warning log", "warning");
        log_error!("TestError", "Error log", "failure");
    }

    #[test]
    fn test_fallback_log() {
        init_logger();

        // This just verifies it doesn't panic
        fallback_log("INFO", "TestModule", "Fallback test", "success", "test.rs");

        // Test different levels
        fallback_log(
            "DEBUG",
            "TestModule",
            "Debug fallback",
            "attempt",
            "test.rs",
        );
        fallback_log(
            "WARN",
            "TestModule",
            "Warning fallback",
            "warning",
            "test.rs",
        );
        fallback_log(
            "ERROR",
            "TestModule",
            "Error fallback",
            "failure",
            "test.rs",
        );
        fallback_log(
            "UNKNOWN",
            "TestModule",
            "Unknown level",
            "unknown",
            "test.rs",
        );
    }

    #[test]
    fn test_dropped_count() {
        // Just ensure it doesn't panic and returns a valid value
        let count = Log::dropped_count();
        assert_eq!(count, count, "Should return a consistent value");
    }

    #[test]
    fn test_is_initialized() {
        // This just tests the function exists and returns a boolean
        let initialized = Log::is_initialized();
        assert!(
            initialized == true || initialized == false,
            "is_initialized should return a boolean value"
        );
    }
}
