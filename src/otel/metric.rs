//! An OpenTelemetry (metric) layer for HTTP services.
//!
//! The implementation follows the [OpenTelemetry Semantic Conventions].
//!
//! [OpenTelemetry Semantic Conventions]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/http/http-metrics.md

// TODO parse Host header to populate `server.address` and `server.port`
// TODO better detect of use_tls

use std::{
    borrow::Cow,
    fmt::Display,
    future::Future,
    pin::Pin,
    sync::{Arc, Weak},
    task::{ready, Context, Poll},
    time::Instant,
};

use opentelemetry::{
    metrics::{Counter, Histogram, MeterProvider, Unit, UpDownCounter},
    Key, KeyValue, Value,
};
use opentelemetry_sdk::metrics::{new_view, Aggregation, Instrument, SdkMeterProvider, Stream};
use pin_project_lite::pin_project;
use tower_layer::Layer;
use tower_service::Service;

use super::{http_method_label, http_version_label};

const HTTP_SERVER_REQUEST_DURATION: &str = "http.server.request.duration";
const HTTP_CLIENT_REQUEST_DURATION: &str = "http.client.request.duration";

const HTTP_SERVER_REQUEST_COUNT: &str = "http.server.request.count";
const HTTP_CLIENT_REQUEST_COUNT: &str = "http.client.request.count";

const HTTP_SERVER_ACTIVE_REQUESTS: &str = "http.server.active_requests";
const HTTP_CLIENT_ACTIVE_REQUESTS: &str = "http.client.active_requests";

const HTTP_REQUEST_DURATION_HISTOGRAM_BUCKETS: &[f64] = &[
    0.0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

const ERROR_TYPE: Key = Key::from_static_str("error.type");
const HTTP_REQUEST_METHOD: Key = Key::from_static_str("http.request.method");
const HTTP_RESPONSE_STATUS_CODE: Key = Key::from_static_str("http.response.status_code");
const NETWORK_PROTOCOL_NAME: Key = Key::from_static_str("network.protocol.name");
const NETWORK_PROTOCOL_VERSION: Key = Key::from_static_str("network.protocol.version");
const URL_SCHEME: Key = Key::from_static_str("url.scheme");

/// Describe the role of the service producing metrics.
#[derive(Clone, Copy, Debug)]
enum MetricKind {
    /// The metric is produced on client side.
    Client,
    /// The metric is produced on server side.
    Server,
}

/// [`Metrics`] builder.
pub struct MetricsBuilder {
    /// The role of the service producing metrics.
    kind: MetricKind,
    /// True if TLS is enabled.
    use_tls: bool,
    /// Metric prefix.
    metric_prefix: Option<Cow<'static, str>>,
}

impl MetricsBuilder {
    /// Create a new [`MetricsBuilder`] for the given side with default values.
    fn new(kind: MetricKind) -> Self {
        Self {
            kind,
            use_tls: false,
            metric_prefix: None,
        }
    }

    /// Add the given prefix to the metric's names.
    pub fn with_prefix<P>(mut self, prefix: P) -> Self
    where
        P: Into<Cow<'static, str>>,
    {
        self.metric_prefix = Some(prefix.into());
        self
    }

    /// Set if the protocol to be https.
    pub fn with_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = use_tls;
        self
    }
}

impl MetricsBuilder {
    /// Build a new [`Metrics`].
    pub fn build(self) -> Metrics {
        // TODO prometheus exporter can be customized with Registry::new_custom(...)
        let registry = prometheus::Registry::new();
        let reader = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .unwrap();

        let http_request_duration_instrument = match self.kind {
            MetricKind::Server => format!("*{HTTP_SERVER_REQUEST_DURATION}"),
            MetricKind::Client => format!("*{HTTP_CLIENT_REQUEST_DURATION}"),
        };

        // TODO provided can be customized with some resources
        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_view(
                new_view(
                    Instrument::new().name(http_request_duration_instrument),
                    Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: HTTP_REQUEST_DURATION_HISTOGRAM_BUCKETS.to_vec(),
                        record_min_max: true,
                    }),
                )
                .unwrap(),
            )
            .build();

        // meters definition
        let meter = provider.meter("");
        let request_duration = meter
            .f64_histogram(match self.kind {
                MetricKind::Server => HTTP_SERVER_REQUEST_DURATION,
                MetricKind::Client => HTTP_CLIENT_REQUEST_DURATION,
            })
            .with_unit(Unit::new("s"))
            .with_description(match self.kind {
                MetricKind::Server => "Duration of HTTP server requests.",
                MetricKind::Client => "Duration of HTTP client requests.",
            })
            .init();
        let request_count = meter
            .u64_counter(match self.kind {
                MetricKind::Server => HTTP_SERVER_REQUEST_COUNT,
                MetricKind::Client => HTTP_CLIENT_REQUEST_COUNT,
            })
            .with_description(match self.kind {
                MetricKind::Server => "The total number of requests received from the server.",
                MetricKind::Client => "The total number of requests sent from the client.",
            })
            .init();
        let request_active = meter
            .i64_up_down_counter(match self.kind {
                MetricKind::Server => HTTP_SERVER_ACTIVE_REQUESTS,
                MetricKind::Client => HTTP_CLIENT_ACTIVE_REQUESTS,
            })
            .with_description(match self.kind {
                MetricKind::Server => "The number of active requests in flight on the server.",
                MetricKind::Client => "The number of active requests in flight on the client.",
            })
            .init();

        let inner = MetricsInner {
            registry,
            use_tls: self.use_tls,
            request_duration,
            request_count,
            request_active,
        };
        Metrics {
            inner: Arc::new(inner),
        }
    }
}

/// A structure that records and exposes the metrics.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    registry: prometheus::Registry,
    use_tls: bool,
    /// Histogram with request duration in seconds.
    request_duration: Histogram<f64>,
    /// Total nubmer of requets.
    request_count: Counter<u64>,
    /// The number of active requests.
    request_active: UpDownCounter<i64>,
}

impl Metrics {
    /// Create a new [`MetricsBuilder`] for server side.
    pub fn server() -> MetricsBuilder {
        MetricsBuilder::new(MetricKind::Server)
    }

    /// Create a new [`MetricsBuilder`] for client side.
    pub fn client() -> MetricsBuilder {
        MetricsBuilder::new(MetricKind::Client)
    }

    /// Build a new [`MetricLayer`].
    pub fn layer(&self) -> MetricLayer {
        MetricLayer::new(self)
    }

    /// Export metrics for Prometheus.
    pub fn export_metrics(&self) -> String {
        prometheus::TextEncoder::new()
            .encode_to_string(&self.inner.registry.gather())
            .unwrap_or_else(|err| format!("# failed to export metrics: {err}"))
    }
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricRecords")
            .field("registry", &self.inner.registry)
            .finish()
    }
}

/// [`Layer`] that adds metric recording to a [`Service`] that handles HTTP requests.
///
/// [`Layer`]: tower_layer::Layer
/// [`Service`]: tower_service::Service
#[derive(Clone, Debug)]
pub struct MetricLayer {
    records: Weak<MetricsInner>,
}

impl MetricLayer {
    /// Create a new [`MetricLayer`] with a given records.
    fn new(records: &Metrics) -> Self {
        Self {
            records: Arc::downgrade(&records.inner),
        }
    }
}

impl<S> Layer<S> for MetricLayer {
    type Service = MetricService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricService {
            inner,
            records: self.records.clone(),
        }
    }
}

/// Middleware that records the metrics of a [`Service`] that handles HTTP requests.
///
/// [`Service`]: tower_service::Service
#[derive(Clone, Debug)]
pub struct MetricService<S> {
    inner: S,
    records: Weak<MetricsInner>,
}

impl<S, Req, Res> Service<http::Request<Req>> for MetricService<S>
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

    fn call(&mut self, req: http::Request<Req>) -> Self::Future {
        let http_method = req.method().clone();
        let http_version = req.version();

        let request_start = Instant::now();
        let inner = self.inner.call(req);

        if let Some(records) = self.records.upgrade() {
            let labels = &[
                KeyValue {
                    key: HTTP_REQUEST_METHOD,
                    value: Value::from(http_method_label(&http_method)),
                },
                KeyValue {
                    key: URL_SCHEME,
                    value: Value::from(if records.use_tls { "https" } else { "http" }),
                },
            ];
            records.request_active.add(1, labels);
        }
        ResponseFuture {
            inner,
            records: self.records.clone(),
            http_method,
            http_version,
            request_start,
        }
    }
}

pin_project! {
    /// Response future for [`Metric`].
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
        records: Weak<MetricsInner>,
        http_method: http::Method,
        http_version: http::Version,
        request_start: Instant,
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
        let res = ready!(this.inner.poll(cx));
        if let Some(records) = this.records.upgrade() {
            let mut labels = heapless::Vec::<KeyValue, 4>::new();
            unsafe {
                labels.push_unchecked(KeyValue {
                    key: HTTP_REQUEST_METHOD,
                    value: Value::from(http_method_label(this.http_method)),
                });
                labels.push_unchecked(KeyValue {
                    key: NETWORK_PROTOCOL_NAME,
                    value: Value::from("http"),
                });
                if let Some(http_version) = http_version_label(this.http_version) {
                    labels.push_unchecked(KeyValue {
                        key: NETWORK_PROTOCOL_VERSION,
                        value: Value::from(http_version),
                    });
                }
                labels.push_unchecked(match &res {
                    Ok(res) => KeyValue {
                        key: HTTP_RESPONSE_STATUS_CODE,
                        value: Value::I64(res.status().as_u16() as i64),
                    },
                    Err(err) => KeyValue {
                        key: ERROR_TYPE,
                        value: Value::from(err.to_string()),
                    },
                });
                labels.push_unchecked(KeyValue {
                    key: URL_SCHEME,
                    value: Value::from(if records.use_tls { "https" } else { "http" }),
                })
            }

            let request_duration = this.request_start.elapsed().as_secs_f64();
            records.request_duration.record(request_duration, &labels);
            records.request_count.add(1, &labels);

            let labels = &[
                KeyValue {
                    key: HTTP_REQUEST_METHOD,
                    value: Value::from(http_method_label(this.http_method)),
                },
                KeyValue {
                    key: URL_SCHEME,
                    value: Value::from(if records.use_tls { "https" } else { "http" }),
                },
            ];
            records.request_active.add(-1, labels);
        }

        Poll::Ready(res)
    }
}
