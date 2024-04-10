//! An OpenTelemetry layer for HTTP services.

use std::{
    fmt::Display,
    future::Future,
    pin::Pin,
    str::FromStr,
    task::{ready, Context, Poll},
};

use pin_project_lite::pin_project;
use tower_layer::Layer;
use tower_service::Service;
use tracing::{field::DisplayValue, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

// Opentelemetry semantic conventions
const ERROR_MESSAGE: &str = "error.message";
const HTTP_REQUEST_METHOD: &str = "http.request.method";
const HTTP_REQUEST_HEADER: &str = "http.request.header";
const HTTP_RESPONSE_HEADER: &str = "http.response.header";
const HTTP_RESPONSE_STATUS_CODE: &str = "http.response.status_code";
const NETWORK_PROTOCOL_NAME: &str = "network.protocol.name";
const NETWORK_PROTOCOL_VERSION: &str = "network.protocol.version";
const OTEL_KIND: &str = "otel.kind";
const OTEL_STATUS_CODE: &str = "otel.status_code";
const URL_FULL: &str = "url.full";
const URL_PATH: &str = "url.path";
const URL_QUERY: &str = "url.query";

/// Describe the relationship between the [`Span`] and the service producing the span.
///
/// [`Span`]: tracing::Span
#[derive(Clone, Copy, Debug)]
enum SpanKind {
    /// The span describes a request sent to some remote service.
    Client,
    /// The span describes the server-side handling of a request.
    Server,
}

/// [`Layer`] that adds tracing to a [`Service`] that handles HTTP requests.
///
/// [`Layer`]: tower_layer::Layer
/// [`Service`]: tower_service::Service
#[derive(Clone, Debug)]
pub struct TracingLayer {
    level: Level,
    kind: SpanKind,
}

impl TracingLayer {
    /// [`Span`]s are constructed at the given level from server side.
    ///
    /// [`Span`]: tracing::Span
    pub fn server(level: Level) -> Self {
        Self {
            level,
            kind: SpanKind::Server,
        }
    }

    /// [`Span`]s are constructed at the given level from client side.
    ///
    /// [`Span`]: tracing::Span
    pub fn client(level: Level) -> Self {
        Self {
            level,
            kind: SpanKind::Client,
        }
    }
}

impl<S> Layer<S> for TracingLayer {
    type Service = Tracing<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Tracing {
            inner,
            level: self.level,
            kind: self.kind,
        }
    }
}

/// Middleware that adds tracing to a [`Service`] that handles HTTP requests.
///
/// [`Service`]: tower_service::Service
#[derive(Clone, Debug)]
pub struct Tracing<S> {
    inner: S,
    level: Level,
    kind: SpanKind,
}

impl<S, Req, Res> Service<http::Request<Req>> for Tracing<S>
where
    S: Service<http::Request<Req>, Response = http::Response<Res>>,
    S::Error: Display,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<Req>) -> Self::Future {
        let span = make_request_span(self.level, self.kind, &mut req);
        let inner = {
            let _enter = span.enter();
            self.inner.call(req)
        };

        ResponseFuture {
            inner,
            span,
            kind: self.kind,
        }
    }
}

pin_project! {
    /// Response future for [`Tracing`].
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
        span: Span,
        kind: SpanKind,
    }
}

impl<F, Res, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<http::Response<Res>, E>>,
    E: Display,
{
    type Output = Result<http::Response<Res>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let _enter = this.span.enter();

        match ready!(this.inner.poll(cx)) {
            Ok(response) => {
                record_response(this.span, *this.kind, &response);
                Poll::Ready(Ok(response))
            }
            Err(err) => {
                record_error(this.span, &err);
                Poll::Ready(Err(err))
            }
        }
    }
}

/// Creates a new [`Span`] for the request.
///
/// [`Span`]: tracing::Span
fn make_request_span<Req>(level: Level, kind: SpanKind, req: &mut http::Request<Req>) -> Span {
    macro_rules! make_span {
        ($level:expr) => {{
            use tracing::field::Empty;

            tracing::span!(
                $level,
                "HTTP",
                { ERROR_MESSAGE } = Empty,
                { HTTP_REQUEST_METHOD } = http_method(req.method()),
                { HTTP_RESPONSE_STATUS_CODE } = Empty,
                { NETWORK_PROTOCOL_NAME } = "http",
                { NETWORK_PROTOCOL_VERSION } = http_version(req.version()),
                { OTEL_KIND } = span_kind(kind),
                { OTEL_STATUS_CODE } = Empty,
                { URL_FULL } = request_full_url(kind, req.uri()),
                { URL_PATH } = req.uri().path(),
                { URL_QUERY } = req.uri().query(),
            )
        }};
    }

    let span = match level {
        Level::ERROR => make_span!(Level::ERROR),
        Level::WARN => make_span!(Level::WARN),
        Level::INFO => make_span!(Level::INFO),
        Level::DEBUG => make_span!(Level::DEBUG),
        Level::TRACE => make_span!(Level::TRACE),
    };

    for (header_name, header_value) in req.headers() {
        if let Ok(attribute_value) = header_value.to_str() {
            let attribute_name = format!("{HTTP_REQUEST_HEADER}.{header_name}");
            let attribute_value = attribute_value.to_string();
            span.set_attribute(attribute_name, attribute_value);
        }
    }

    match kind {
        SpanKind::Client => {
            let ctx = span.context();
            opentelemetry::global::get_text_map_propagator(|injector| {
                injector.inject_context(&ctx, &mut HeaderInjector(req.headers_mut()))
            });
        }
        SpanKind::Server => {
            let ctx = opentelemetry::global::get_text_map_propagator(|extractor| {
                extractor.extract(&HeaderExtractor(req.headers_mut()))
            });
            span.set_parent(ctx);
        }
    }

    span
}

/// Records fields associated to the response.
fn record_response<Res>(span: &Span, kind: SpanKind, res: &http::Response<Res>) {
    span.record(HTTP_RESPONSE_STATUS_CODE, res.status().as_u16() as i64);

    for (header_name, header_value) in res.headers() {
        if let Ok(attribute_value) = header_value.to_str() {
            let attribute_name = format!("{HTTP_RESPONSE_HEADER}.{header_name}");
            let attribute_value = attribute_value.to_string();
            span.set_attribute(attribute_name, attribute_value);
        }
    }

    let status_code = match kind {
        SpanKind::Client if res.status().is_client_error() => "ERROR",
        _ if res.status().is_server_error() => "ERROR",
        _ => "OK",
    };
    span.record(OTEL_STATUS_CODE, status_code);
}

/// Records the error message.
fn record_error<E: Display>(span: &Span, err: &E) {
    span.record(OTEL_STATUS_CODE, "ERROR")
        .record(ERROR_MESSAGE, err.to_string());
}

/// Representation of request full url.
fn request_full_url(kind: SpanKind, uri: &http::Uri) -> Option<DisplayValue<&http::Uri>> {
    use tracing::field::display;

    match kind {
        SpanKind::Client => Some(display(uri)),
        _ => None,
    }
}

/// String representation of HTTP method
fn http_method(method: &http::Method) -> Option<&'static str> {
    match *method {
        http::Method::GET => Some("GET"),
        http::Method::POST => Some("POST"),
        http::Method::PUT => Some("PUT"),
        http::Method::DELETE => Some("DELETE"),
        http::Method::HEAD => Some("HEAD"),
        http::Method::OPTIONS => Some("OPTIONS"),
        http::Method::CONNECT => Some("CONNECT"),
        http::Method::PATCH => Some("PATCH"),
        http::Method::TRACE => Some("TRACE"),
        _ => None,
    }
}

/// String representation of network protocol version
fn http_version(version: http::Version) -> Option<&'static str> {
    match version {
        http::Version::HTTP_09 => Some("0.9"),
        http::Version::HTTP_10 => Some("1.0"),
        http::Version::HTTP_11 => Some("1.1"),
        http::Version::HTTP_2 => Some("2"),
        http::Version::HTTP_3 => Some("3"),
        _ => None,
    }
}

/// String representation of span kind
fn span_kind(kind: SpanKind) -> &'static str {
    match kind {
        SpanKind::Client => "client",
        SpanKind::Server => "server",
    }
}

/// Helper to inject headers in HTTP request.
pub struct HeaderInjector<'a>(pub &'a mut http::HeaderMap);

impl<'a> opentelemetry::propagation::Injector for HeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(header_name) = http::HeaderName::from_str(key) {
            if let Ok(header_value) = http::HeaderValue::from_str(&value) {
                self.0.insert(header_name, header_value);
            }
        }
    }
}

/// Helper to extract headers from HTTP request.
pub struct HeaderExtractor<'a>(pub &'a http::HeaderMap);

impl<'a> opentelemetry::propagation::Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .and_then(|header_value| header_value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(|header_name| header_name.as_str())
            .collect()
    }
}
