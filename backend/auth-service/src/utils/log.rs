//! Simple structured logging for auth service.
//!
//! Provides a single consistent format for log messages with an "origin" field that specifies the source file.
//! Logs are written to both stdout (via log crate) and a log file for collection by Filebeat asynchronously.

use log::{info, warn, error, debug};
use serde_json::json;
use chrono::Utc;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::thread;
use crossbeam_channel::{bounded, Sender};
use once_cell::sync::Lazy;

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
    // Create a bounded channel with appropriate capacity
    let (sender, receiver) = bounded::<LogMessage>(10000);
    
    // Spawn a background thread for processing logs
    let _ = thread::Builder::new()
        .name("log-processor".to_string())
        .spawn(move || {
            // Initialize the file handle
            let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "logs".to_string());
            let log_file_path = format!("{}/auth-service.log", log_dir);
            
            // Create logs directory if it doesn't exist
            if !Path::new(&log_dir).exists() {
                if let Err(e) = std::fs::create_dir_all(&log_dir) {
                    eprintln!("Warning: Could not create log directory: {}", e);
                    return;
                }
            }
            
            // Try to open the log file
            let file = match OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(&log_file_path) {
                    Ok(file) => file,
                    Err(e) => {
                        eprintln!("Warning: Could not open log file: {}", e);
                        return;
                    }
                };
            
            // Create a buffered writer for better performance
            let mut writer = BufWriter::with_capacity(8192, file);
            
            // Process logs from the channel
            while let Ok(message) = receiver.recv() {
                // Process the log message
                let timestamp = Utc::now().to_rfc3339();
                
                // Create the structured log object
                let log_data = json!({
                    "service": "auth-service",
                    "process": message.process,
                    "event": message.event,
                    "result": message.result,
                    "level": message.level,
                    "timestamp": timestamp,
                    "origin": {
                        "file": message.origin
                    }
                });
                
                let log_str = log_data.to_string();
                
                // Log to console through standard log macros
                match message.level.as_str() {
                    "DEBUG" => debug!("{}", log_str),
                    "INFO"  => info!("{}", log_str),
                    "WARN"  => warn!("{}", log_str),
                    "ERROR" => error!("{}", log_str),
                    _       => warn!("Unknown log level: {}", log_str),
                }
                
                // Write to the file
                if let Err(_) = writeln!(writer, "{}", log_str) {
                    // If writing fails, try to reopen the file
                    // This handles cases where the file might have been deleted/rotated
                    if let Ok(new_file) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .write(true)
                        .open(&log_file_path) {
                        writer = BufWriter::with_capacity(8192, new_file);
                        let _ = writeln!(writer, "{}", log_str);
                    }
                }
                
                // Periodically flush - every ~10 log messages
                // This balances between performance and durability
                if receiver.len() % 10 == 0 {
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
            // Create log message
            let message = LogMessage {
                level: level.to_string(),
                process: process.to_string(),
                event: event.to_string(),
                result: result.to_string(),
                origin: origin.to_string(),
            };
            
            // Try to send the log message, but don't block if the channel is full
            let _ = channel.sender.try_send(message);
        } else {
            // Fallback if the channel isn't initialized
            // This should rarely happen
            let timestamp = Utc::now().to_rfc3339();
            let log_data = json!({
                "service": "auth-service",
                "process": process,
                "event": event,
                "result": result,
                "level": level,
                "timestamp": timestamp,
                "origin": {
                    "file": origin
                }
            });
            
            let log_str = log_data.to_string();
            match level {
                "DEBUG" => debug!("{}", log_str),
                "INFO"  => info!("{}", log_str),
                "WARN"  => warn!("{}", log_str),
                "ERROR" => error!("{}", log_str),
                _       => warn!("Unknown log level: {}", log_str),
            }
        }
    }
    
    /// Initialize the logging system.
    /// This ensures the log directory exists and the log file is ready.
    pub fn init() -> io::Result<()> {
        // Force initialization of the lazy static
        let _ = &*LOG_CHANNEL;
        Ok(())
    }
}

// Macros remain unchanged
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