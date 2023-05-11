/// Most of this code is from https://github.com/tokio-rs/axum/pull/769.
use anyhow::Result;
use axum::http::{header, HeaderMap, Method, Request};
use axum::{
    extract::{ConnectInfo, MatchedPath, OriginalUri},
    response::Response,
};
use opentelemetry::{
    sdk::propagation::TraceContextPropagator,
    sdk::{
        trace::{self, Sampler},
        Resource,
    },
    KeyValue,
};
use std::{borrow::Cow, net::SocketAddr, time::Duration};
use tower_http::{
    classify::{ServerErrorsAsFailures, ServerErrorsFailureClass, SharedClassifier},
    trace::{MakeSpan, OnBodyChunk, OnEos, OnFailure, OnRequest, OnResponse, TraceLayer},
};
use tracing::{field::Empty, Span};
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::app_config::{AppConfig, LogFormat};

pub fn init(config: &AppConfig) -> Result<()> {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let sampler = match config.oltp_endpoint {
        Some(_) => Sampler::AlwaysOn,
        None => Sampler::AlwaysOff,
    };

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .with_trace_config(
            trace::config()
                .with_sampler(sampler)
                .with_resource(Resource::new(vec![KeyValue::new("service.name", "tfreg")])),
        )
        .install_batch(opentelemetry::runtime::Tokio)?;

    tracing_subscriber::registry()
        .with(logging_layer(&config.log_format))
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .with(tracing_subscriber::EnvFilter::new(&config.log_level))
        .try_init()?;

    Ok(())
}

/// Construct a fmt layer based on the logging format requested.
///
/// Ref: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/index.html#runtime-configuration-with-layers
fn logging_layer<S>(log_format: &LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let json = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .flatten_event(true)
        .with_target(false)
        .with_span_list(false)
        .boxed();
    let pretty = tracing_subscriber::fmt::layer().pretty().boxed();
    let compact = tracing_subscriber::fmt::layer().compact().boxed();
    match log_format {
        LogFormat::Compact => compact,
        LogFormat::Pretty => pretty,
        LogFormat::Json => json,
    }
}

/// OpenTelemetry tracing middleware.
///
/// This returns a [`TraceLayer`] configured to use [OpenTelemetry's conventional span field
/// names][otel].
///
/// # Span fields
///
/// The following fields will be set on the span:
///
/// - `http.client_ip`: The client's IP address. Requires using
/// [`Router::into_make_service_with_connect_info`]
/// - `http.host`: The value of the `Host` header
/// - `http.method`: The request method
/// - `http.route`: The matched route
/// - `http.scheme`: The URI scheme used (`HTTP` or `HTTPS`)
/// - `http.status_code`: The response status code
/// - `http.target`: The full request target including path and query parameters
/// - `http.user_agent`: The value of the `User-Agent` header
/// - `otel.kind`: Always `server`
/// - `otel.status_code`: `OK` if the response is success, `ERROR` if it is a 5xx
/// - `trace_id`: The trace id as tracted via the remote span context.
///
/// # Example
///
/// ```
/// use axum::{Router, routing::get, http::Request};
/// use axum_extra::middleware::opentelemetry_tracing_layer;
/// use std::net::SocketAddr;
/// use tower::ServiceBuilder;
///
/// let app = Router::new()
///     .route("/", get(|| async {}))
///     .layer(opentelemetry_tracing_layer());
///
/// # async {
/// axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
///     // we must use `into_make_service_with_connect_info` for `opentelemetry_tracing_layer` to
///     // access the client ip
///     .serve(app.into_make_service_with_connect_info::<SocketAddr, _>())
///     .await
///     .expect("server failed");
/// # };
/// ```
///
/// # Complete example
///
/// See the "opentelemetry-jaeger" example for a complete setup that includes an OpenTelemetry
/// pipeline sending traces to jaeger.
///
/// [otel]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/http.md
/// [`Router::into_make_service_with_connect_info`]: axum::Router::into_make_service_with_connect_info
pub fn opentelemetry_tracing_layer() -> TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    OtelMakeSpan,
    OtelOnRequest,
    OtelOnResponse,
    OtelOnBodyChunk,
    OtelOnEos,
    OtelOnFailure,
> {
    TraceLayer::new_for_http()
        .make_span_with(OtelMakeSpan)
        .on_request(OtelOnRequest)
        .on_response(OtelOnResponse)
        .on_body_chunk(OtelOnBodyChunk)
        .on_eos(OtelOnEos)
        .on_failure(OtelOnFailure)
}

/// A [`MakeSpan`] that creates tracing spans using [OpenTelemetry's conventional field names][otel].
///
/// [otel]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/http.md
#[derive(Clone, Copy, Debug)]
pub struct OtelMakeSpan;

impl<B> MakeSpan<B> for OtelMakeSpan {
    fn make_span(&mut self, req: &Request<B>) -> Span {
        let user_agent = req
            .headers()
            .get(header::USER_AGENT)
            .map_or("", |h| h.to_str().unwrap_or(""));

        let host = req
            .headers()
            .get(header::HOST)
            .map_or("", |h| h.to_str().unwrap_or(""));

        let http_route = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
            matched_path.as_str().to_owned()
        } else if let Some(uri) = req.extensions().get::<OriginalUri>() {
            uri.0.path().to_owned()
        } else {
            req.uri().path().to_owned()
        };

        let uri = if let Some(uri) = req.extensions().get::<OriginalUri>() {
            uri.0.clone()
        } else {
            req.uri().clone()
        };
        let http_target = uri.path();

        let client_ip = parse_x_forwarded_for(req.headers())
            .or_else(|| {
                req.extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ConnectInfo(client_ip)| Cow::from(client_ip.to_string()))
            })
            .unwrap_or_default();

        let remote_context = extract_remote_context(req.headers());
        let span = tracing::info_span!(
            "HTTP request",
            http.client_ip = %client_ip,
            http.host = %host,
            http.method = %http_method(req.method()),
            http.route = %http_route,
            http.status_code = Empty,
            http.target = %http_target,
            http.user_agent = %user_agent,
            otel.kind = "server",
            otel.status_code = Empty,
        );

        tracing_opentelemetry::OpenTelemetrySpanExt::set_parent(&span, remote_context);

        span
    }
}

fn parse_x_forwarded_for(headers: &HeaderMap) -> Option<Cow<'_, str>> {
    let value = headers.get("x-forwarded-for")?;
    let value = value.to_str().ok()?;
    let mut ips = value.split(',');
    Some(ips.next()?.trim().into())
}

fn http_method(method: &Method) -> Cow<'static, str> {
    match method {
        &Method::CONNECT => "CONNECT".into(),
        &Method::DELETE => "DELETE".into(),
        &Method::GET => "GET".into(),
        &Method::HEAD => "HEAD".into(),
        &Method::OPTIONS => "OPTIONS".into(),
        &Method::PATCH => "PATCH".into(),
        &Method::POST => "POST".into(),
        &Method::PUT => "PUT".into(),
        &Method::TRACE => "TRACE".into(),
        other => other.to_string().into(),
    }
}

// If remote request has no span data the propagator defaults to an unsampled context
fn extract_remote_context(headers: &axum::http::HeaderMap) -> opentelemetry::Context {
    struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

    impl<'a> opentelemetry::propagation::Extractor for HeaderExtractor<'a> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|value| value.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|value| value.as_str()).collect()
        }
    }

    let extractor = HeaderExtractor(headers);
    opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(&extractor))
}

/// Callback that [`Trace`] will call when it receives a request.
///
/// [`Trace`]: tower_http::trace::Trace
#[derive(Clone, Copy, Debug)]
pub struct OtelOnRequest;

impl<B> OnRequest<B> for OtelOnRequest {
    #[inline]
    fn on_request(&mut self, _request: &Request<B>, _span: &Span) {}
}

/// Callback that [`Trace`] will call when it receives a response.
///
/// [`Trace`]: tower_http::trace::Trace
#[derive(Clone, Copy, Debug)]
pub struct OtelOnResponse;

impl<B> OnResponse<B> for OtelOnResponse {
    fn on_response(self, response: &Response<B>, _latency: Duration, span: &Span) {
        let status = response.status().as_u16().to_string();
        span.record("http.status_code", &tracing::field::display(status));

        // assume there is no error, if there is `OtelOnFailure` will be called and override this
        span.record("otel.status_code", "OK");
        tracing::info!("Request finished");
    }
}

/// Callback that [`Trace`] will call when the response body produces a chunk.
///
/// [`Trace`]: tower_http::trace::Trace
#[derive(Clone, Copy, Debug)]
pub struct OtelOnBodyChunk;

impl<B> OnBodyChunk<B> for OtelOnBodyChunk {
    #[inline]
    fn on_body_chunk(&mut self, _chunk: &B, _latency: Duration, _span: &Span) {}
}

/// Callback that [`Trace`] will call when a streaming response completes.
///
/// [`Trace`]: tower_http::trace::Trace
#[derive(Clone, Copy, Debug)]
pub struct OtelOnEos;

impl OnEos for OtelOnEos {
    #[inline]
    fn on_eos(
        self,
        _trailers: Option<&axum::http::HeaderMap>,
        _stream_duration: Duration,
        _span: &Span,
    ) {
    }
}

/// Callback that [`Trace`] will call when a response or end-of-stream is classified as a failure.
///
/// [`Trace`]: tower_http::trace::Trace
#[derive(Clone, Copy, Debug)]
pub struct OtelOnFailure;

impl OnFailure<ServerErrorsFailureClass> for OtelOnFailure {
    fn on_failure(&mut self, failure: ServerErrorsFailureClass, _latency: Duration, span: &Span) {
        span.record("error", true);
        match failure {
            ServerErrorsFailureClass::StatusCode(status) => {
                if status.is_server_error() {
                    span.record("otel.status_code", "ERROR");
                }
            }
            ServerErrorsFailureClass::Error(_) => {
                span.record("otel.status_code", "ERROR");
            }
        }
    }
}
