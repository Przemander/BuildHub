use std::error::Error;
use opentelemetry::{global, KeyValue};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use opentelemetry_otlp::{SpanExporter, LogExporter, WithExportConfig};
use opentelemetry_sdk::{
    trace::SdkTracerProvider,
    logs::{BatchLogProcessor, SdkLoggerProvider},
    resource::Resource,
};
use opentelemetry_appender_log::OpenTelemetryLogBridge;
use tracing_subscriber::{prelude::*, EnvFilter};
use tracing_opentelemetry::OpenTelemetryLayer;
use tokio::runtime::Runtime;
use opentelemetry::trace::TracerProvider;


pub fn init_otel(rt: &Runtime) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // 1) Resource
    let resource = Resource::builder()
        .with_attributes(vec![
            KeyValue::new(SERVICE_NAME, "auth-service"),
            KeyValue::new(SERVICE_VERSION, "1.0.0"),
        ])
        .build();

    // 2) Traces: build OTLP Span exporter and tracer provider
    let span_exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint("http://localhost:4317")
        .build()?;                                    // only one arg here :contentReference[oaicite:0]{index=0}

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)           // removed the runtime handle :contentReference[oaicite:1]{index=1}
        .with_resource(resource.clone())
        .build();
    global::set_tracer_provider(tracer_provider.clone());

    // 3) Logs: build OTLP Log exporter + SDK LoggerProvider with a batch processor
    let log_exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint("http://localhost:4317")
        .build()?;                                    // no extra args

    let logger_provider = SdkLoggerProvider::builder()
        .with_log_processor(BatchLogProcessor::builder(log_exporter).build())  // use BatchLogProcessor :contentReference[oaicite:2]{index=2}
        .with_resource(resource)
        .build();

    // bridge `log` crate into OpenTelemetry
    let otel_log_appender = OpenTelemetryLogBridge::new(&logger_provider);
    log::set_boxed_logger(Box::new(otel_log_appender)).unwrap();
    log::set_max_level(log::LevelFilter::Info);       // variant is `Info`

    // 4) tracing_subscriber: wire up the OTLP‐tracer as a layer
    let tracer = tracer_provider.tracer("auth-service");   
    let otel_layer = OpenTelemetryLayer::new(tracer);  // supply a `Tracer`, not the provider :contentReference[oaicite:3]{index=3}
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_file(true)
        .with_line_number(true)
        .with_target(true);

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(otel_layer)
        .with(fmt_layer)
        .init();

    Ok(())
}
