//! Production-ready structured logging for BuildHub Auth Service.
//!
//! - Logs are written in JSON format to both stdout and a log file (for Filebeat).
//! - Non-blocking, buffered, and robust against log file rotation/deletion.
//! - All log macros include a file origin for traceability.

use chrono::Utc;
use crossbeam_channel::{bounded, Sender};
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::thread;

// Log message struct for the channel
struct LogMessage {
    level: String,
    process: String,
    event: String,
    result: String,
    origin: String,
}

// Channel for sending log messages
struct LogChannel {
    sender: Sender<LogMessage>,
}

// Global channel for sending log messages
static LOG_CHANNEL: Lazy<Option<LogChannel>> = Lazy::new(|| {
    let (sender, receiver) = bounded::<LogMessage>(10000);

    // Spawn a background thread for processing logs
    let _ = thread::Builder::new()
        .name("log-processor".to_string())
        .spawn(move || {
            let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "logs".to_string());
            let log_file_path = format!("{}/auth-service.log", log_dir);

            // Ensure log directory exists
            if let Err(e) = std::fs::create_dir_all(&log_dir) {
                eprintln!("Warning: Could not create log directory: {}", e);
                return;
            }

            // Open the log file (create if missing)
            let mut writer = match OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(&log_file_path)
                .map(|file| BufWriter::with_capacity(8192, file))
            {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Warning: Could not open log file: {}", e);
                    return;
                }
            };

            let mut counter = 0usize;

            // Process logs from the channel
            while let Ok(message) = receiver.recv() {
                let timestamp = Utc::now().to_rfc3339();

                let log_data = json!({
                    "service": "auth-service",
                    "process": message.process,
                    "event": message.event,
                    "result": message.result,
                    "level": message.level,
                    "timestamp": timestamp,
                    "origin": { "file": message.origin }
                });

                let log_str = log_data.to_string();

                // Log to console through standard log macros
                match message.level.as_str() {
                    "DEBUG" => debug!("{}", log_str),
                    "INFO" => info!("{}", log_str),
                    "WARN" => warn!("{}", log_str),
                    "ERROR" => error!("{}", log_str),
                    _ => warn!("Unknown log level: {}", log_str),
                }

                // Write to the file
                if writeln!(writer, "{}", log_str).is_err() {
                    // Try to reopen the file if writing fails (e.g., after rotation)
                    if let Ok(new_file) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .write(true)
                        .open(&log_file_path)
                    {
                        writer = BufWriter::with_capacity(8192, new_file);
                        let _ = writeln!(writer, "{}", log_str);
                    }
                }

                counter += 1;
                // Periodically flush - every 10 log messages
                if counter % 10 == 0 {
                    let _ = writer.flush();
                }
            }

            // Final flush when the channel is closed
            let _ = writer.flush();
        });

    Some(LogChannel { sender })
});

pub struct Log;

impl Log {
    /// Log an event with structured format.
    /// The `origin` parameter will be included inside an "origin" bracket.
    /// This version is non-blocking and sends the log to a background thread.
    pub fn event(level: &str, process: &str, event: &str, result: &str, origin: &str) {
        if let Some(channel) = &*LOG_CHANNEL {
            let message = LogMessage {
                level: level.to_string(),
                process: process.to_string(),
                event: event.to_string(),
                result: result.to_string(),
                origin: origin.to_string(),
            };
            let _ = channel.sender.try_send(message);
        } else {
            // Fallback if the channel isn't initialized
            let timestamp = Utc::now().to_rfc3339();
            let log_data = json!({
                "service": "auth-service",
                "process": process,
                "event": event,
                "result": result,
                "level": level,
                "timestamp": timestamp,
                "origin": { "file": origin }
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
    }
}

// Macros for ergonomic logging
#[macro_export]
macro_rules! log_debug {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("DEBUG", $process, $event, $result, file!())
    };
}

#[macro_export]
macro_rules! log_info {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("INFO", $process, $event, $result, file!())
    };
}

#[macro_export]
macro_rules! log_warn {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("WARN", $process, $event, $result, file!())
    };
}

#[macro_export]
macro_rules! log_error {
    ($process:expr, $event:expr, $result:expr) => {
        $crate::utils::log::Log::event("ERROR", $process, $event, $result, file!())
    };
}