//! Production-ready structured logging for BuildHub Auth Service.
//!
//! - JSON-formatted logs to stdout and file (for Filebeat).
//! - Non-blocking, buffered, and resilient against file rotation.
//! - Emulates Elastic Common Schema (ECS) fields.

use chrono::Utc;
use crossbeam_channel::{bounded, Sender};
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use serde_json::json;
use std::fs::{create_dir_all, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::thread;

/// Internal representation of a structured log message.
struct LogMessage {
    level: &'static str,
    logger: &'static str,
    message: String,
    outcome: &'static str,
    origin: &'static str,
    timestamp: String,
}

/// Buffered channel for log messages.
static LOG_SENDER: Lazy<Sender<LogMessage>> = Lazy::new(|| {
    let (tx, rx) = bounded(10_000);
    let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "logs".into());
    let file_path = Path::new(&log_dir).join("auth-service.log");

    // Spawn background logger thread
    thread::Builder::new()
        .name("log-processor".into())
        .spawn(move || {
            if let Err(e) = create_dir_all(&log_dir) {
                eprintln!("Warning: could not create log dir {}: {}", log_dir, e);
                return;
            }

            let mut writer = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .map(BufWriter::with_capacity(8 * 1024))
                .unwrap_or_else(|e| {
                    eprintln!("Warning: could not open log file {}: {}", file_path.display(), e);
                    std::io::sink()
                });

            let mut count = 0;
            while let Ok(msg) = rx.recv() {
                let record = json!({
                    "@timestamp": msg.timestamp,
                    "log.level": msg.level,
                    "log.logger": msg.logger,
                    "message": msg.message,
                    "event.outcome": msg.outcome,
                    "service.name": "auth-service",
                    "code.filepath": msg.origin,
                })
                .to_string();

                match msg.level {
                    "DEBUG" => debug!("{}", record),
                    "INFO" => info!("{}", record),
                    "WARN" => warn!("{}", record),
                    "ERROR" => error!("{}", record),
                    _ => warn!("Unknown level {}: {}", msg.level, record),
                }

                if writeln!(writer, "{}", record).is_err() {
                    // Attempt reopen on failure
                    if let Ok(file) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&file_path)
                    {
                        writer = BufWriter::with_capacity(8 * 1024, file);
                        let _ = writeln!(writer, "{}", record);
                    }
                }

                count += 1;
                if count % 10 == 0 {
                    let _ = writer.flush();
                }
            }
            let _ = writer.flush();
        })
        .expect("Failed to spawn log thread");

    tx
});

/// Central logger entry point.
pub struct Logger;

impl Logger {
    /// Logs a structured event asynchronously.
    #[inline]
    pub fn log(
        level: &'static str,
        logger: &'static str,
        message: impl Into<String>,
        outcome: &'static str,
        origin: &'static str,
    ) {
        let msg = LogMessage {
            level,
            logger,
            message: message.into(),
            outcome,
            origin,
            timestamp: Utc::now().to_rfc3339(),
        };
        let _ = LOG_SENDER.try_send(msg);
    }
}

// Re-export macros for convenience
#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $msg:expr, $outcome:expr) => {
        $crate::utils::log::Logger::log("DEBUG", $logger, $msg, $outcome, file!())
    };
}

#[macro_export]
macro_rules! log_info {
    ($logger:expr, $msg:expr, $outcome:expr) => {
        $crate::utils::log::Logger::log("INFO", $logger, $msg, $outcome, file!())
    };
}

#[macro_export]
macro_rules! log_warn {
    ($logger:expr, $msg:expr, $outcome:expr) => {
        $crate::utils::log::Logger::log("WARN", $logger, $msg, $outcome, file!())
    };
}

#[macro_export]
macro_rules! log_error {
    ($logger:expr, $msg:expr, $outcome:expr) => {
        $crate::utils::log::Logger::log("ERROR", $logger, $msg, $outcome, file!())
    };
}
