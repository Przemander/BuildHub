//! OpenTelemetry (OTel) and tracing configuration.
//!
//! This module initializes the global `tracing` subscriber, which handles
//! both standard console logging and exporting trace data to an external
//! collector (e.g., Jaeger)
//! using the OTLP/gRPC protocol.

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _; // Required to call the `.tracer(...)` method
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace as sdktrace, Resource};
use std::env;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Inicjalizuje system telemetrii.
///
/// W zależności od zmiennej środowiskowej `OTEL_ENABLED`, funkcja konfiguruje
/// albo pełny stack OpenTelemetry z eksportem do kolektora, albo uproszczone
/// logowanie do konsoli.
///
/// # Uwaga na wersję API OpenTelemetry
///
/// Ta implementacja jest dostosowana do `opentelemetry v0.22` i `opentelemetry-otlp v0.15`,
/// które wprowadziły znaczące zmiany w API w porównaniu do starszych wersji.
/// Kluczowe zmiany to m.in. użycie wzorca budowniczego (`builder`) dla `TracerProvider`
/// i `Resource`, a także nowy sposób konfiguracji eksportera.
pub fn init_telemetry() -> Result<(), Box<dyn std::error::Error>> {
    // --- 1. Check if OpenTelemetry is enabled ---
    let otel_enabled = env::var("OTEL_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    if !otel_enabled {
        info!("OpenTelemetry is disabled. Using standard logging only.");
        init_standard_tracing();
        return Ok(());
    }

    info!("Initializing OpenTelemetry with Jaeger backend (OTLP/gRPC)");

    // --- 2. Configure global context propagator ---
    // Sets the standard propagation method (e.g., in HTTP headers)
    // for passing trace IDs between services.
    global::set_text_map_propagator(TraceContextPropagator::new());

    // --- 3. Load configuration from environment variables ---
    let endpoint =
        env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_else(|_| "http://localhost:4317".to_string());
    let service_name =
        env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "auth-service".to_string());
    let environment = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());

    // --- 4. Define the Resource ---
    // The resource describes the entity producing telemetry data (our microservice).
    // These attributes will be attached to every trace.
    let resource = Resource::builder()
        .with_attributes(vec![
            KeyValue::new("service.name", service_name),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("deployment.environment", environment),
        ])
        .build();

    // --- 5. Configure the OTLP exporter ---
    // The exporter is responsible for sending data to the OTel collector.
    // We use `tonic` as the gRPC backend.
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()?;

    // --- 6. Configure the Tracer Provider ---
    // The provider combines a span processor (BatchSpanProcessor) and the resource.
    // The BatchSpanProcessor groups spans and sends them in the background for efficiency.
    let provider = sdktrace::SdkTracerProvider::builder()
        .with_span_processor(sdktrace::BatchSpanProcessor::builder(exporter).build())
        .with_resource(resource)
        .build();

    // Get a `Tracer` instance from the provider.
    let tracer = provider.tracer("auth-service");

    // --- 7. Configure `tracing-subscriber` layers ---
    // We combine several layers to achieve the desired functionality:
    // - `EnvFilter`: Filters logs based on the `RUST_LOG` variable.
    // - `fmt_layer`: Formats and prints logs to the console.
    // - `telemetry_layer`: Forwards `tracing` data to the OpenTelemetry system.
    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false).compact();

    Registry::default()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,auth_service=debug,tower_http=debug")),
        )
        .with(fmt_layer)
        .with(telemetry_layer)
        .init();

    // --- 8. Set the global provider ---
    // Registers our provider as the global one, making it available throughout the app.
    let _ = global::set_tracer_provider(provider);

    info!(
        "Inicjalizacja OpenTelemetry zakończona pomyślnie. Endpoint: {}",
        endpoint
    );
    Ok(())
}

/// Inicjalizuje uproszczone logowanie, gdy OpenTelemetry jest wyłączone.
fn init_standard_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .compact()
        .init();
}

/// A function to be called during application shutdown.
pub fn shutdown_telemetry() {
    info!("Shutting down OpenTelemetry...");
    // The OpenTelemetry SdkTracerProvider that was set globally will be shut down
    // automatically when the application exits and the provider is dropped.
    // An explicit call to `global::shutdown_tracer_provider()` was used in older
    // versions but is no longer necessary or available in the same way.
    // The Drop implementation of the provider handles flushing remaining spans.
}
