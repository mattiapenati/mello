//! OpenTelemetry support.

#[doc(inline)]
pub use self::{
    metric::Metrics,
    tracing::{Tracing, TracingLayer},
};

pub mod metric;
pub mod tracing;

/// Returns the label for HTTP method.
fn http_method_label(method: &http::Method) -> &'static str {
    match *method {
        http::Method::CONNECT => "CONNECT",
        http::Method::DELETE => "DELETE",
        http::Method::GET => "GET",
        http::Method::HEAD => "HEAD",
        http::Method::OPTIONS => "OPTIONS",
        http::Method::PATCH => "PATCH",
        http::Method::POST => "POST",
        http::Method::PUT => "PUT",
        http::Method::TRACE => "TRACE",
        _ => "_OTHER",
    }
}

/// Returns the label for HTTP protocol version.
pub(super) fn http_version_label(version: &http::Version) -> Option<&'static str> {
    match *version {
        http::Version::HTTP_09 => Some("0.9"),
        http::Version::HTTP_10 => Some("1.0"),
        http::Version::HTTP_11 => Some("1.1"),
        http::Version::HTTP_2 => Some("2"),
        http::Version::HTTP_3 => Some("3"),
        _ => None,
    }
}
