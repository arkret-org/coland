use coland_http::config::OtelConfig;
use tracing_subscriber::{Layer, Registry};

pub type OtelLayer = Box<dyn Layer<Registry> + Send + Sync>;

#[cfg(feature = "otel")]
pub struct OtelGuard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

#[cfg(not(feature = "otel"))]
pub struct OtelGuard;

#[cfg(feature = "otel")]
impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

#[cfg(feature = "otel")]
pub fn init_layer(
    config: &OtelConfig,
    default_service_name: &str,
) -> anyhow::Result<(OtelGuard, Option<OtelLayer>)> {
    use std::time::Duration;

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::{KeyValue, global};
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

    if !config.exporter_enabled {
        return Ok((OtelGuard { provider: None }, None));
    }

    let endpoint = config.endpoint.clone();
    let timeout_seconds = config.timeout_seconds;
    let sample_ratio = config.sample_ratio;
    let service_name = config
        .service_name
        .clone()
        .unwrap_or_else(|| default_service_name.to_owned());

    global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(timeout_seconds))
        .build()?;
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", service_name.clone()))
        .build();
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(sample_ratio))
        .build();
    let tracer = provider.tracer(service_name);
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    global::set_tracer_provider(provider.clone());

    Ok((
        OtelGuard {
            provider: Some(provider),
        },
        Some(Box::new(layer)),
    ))
}

#[cfg(not(feature = "otel"))]
pub fn init_layer(
    config: &OtelConfig,
    _default_service_name: &str,
) -> anyhow::Result<(OtelGuard, Option<OtelLayer>)> {
    if config.exporter_enabled {
        anyhow::bail!(
            "COLAND_OTEL_EXPORTER is set, but this binary was built without the `otel` feature"
        );
    }
    Ok((OtelGuard, None))
}
