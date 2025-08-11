//! Production-ready structured logging for BuildHub Auth Service with OTel integration.
//!
//! This module integrates custom ECS logging with OpenTelemetry via tracing.
//!
//! # Changes from Original
//! - Uses tracing directly; dropped the old channel model.
//! - Emits trace/span IDs via OTel context.

use opentelemetry::global;
use opentelemetry::trace::{TraceContextExt, Tracer};
use tracing::Level;

/// Service name constant
const SERVICE_NAME: &str = "auth-service";

/// Main logging interface
pub struct Log;

impl Log {
    /// Logs an event with ECS-compliant structured format via tracing/OTel
    pub fn event(level_str: &str, process: &str, message: &str, outcome: &str, origin: &str) {
        // Start a temporary span to extract trace context
        let tracer = global::tracer(SERVICE_NAME);
        let span = tracer.start("log_event");
        let cx = opentelemetry::Context::current_with_span(span);
        let trace_id = cx.span().span_context().trace_id().to_string();
        let span_id = cx.span().span_context().span_id().to_string();

        // Emit structured event with literal level in macro
        match level_str {
            "DEBUG" => tracing::event!(
                Level::DEBUG,
                service = SERVICE_NAME,
                process = process,
                message = message,
                outcome = outcome,
                origin = origin,
                trace_id = trace_id,
                span_id = span_id
            ),
            "INFO" => tracing::event!(
                Level::INFO,
                service = SERVICE_NAME,
                process = process,
                message = message,
                outcome = outcome,
                origin = origin,
                trace_id = trace_id,
                span_id = span_id
            ),
            "WARN" => tracing::event!(
                Level::WARN,
                service = SERVICE_NAME,
                process = process,
                message = message,
                outcome = outcome,
                origin = origin,
                trace_id = trace_id,
                span_id = span_id
            ),
            "ERROR" => tracing::event!(
                Level::ERROR,
                service = SERVICE_NAME,
                process = process,
                message = message,
                outcome = outcome,
                origin = origin,
                trace_id = trace_id,
                span_id = span_id
            ),
            _ => tracing::event!(
                Level::INFO,
                service = SERVICE_NAME,
                process = process,
                message = message,
                outcome = outcome,
                origin = origin,
                trace_id = trace_id,
                span_id = span_id
            ),
        };
    }
}
