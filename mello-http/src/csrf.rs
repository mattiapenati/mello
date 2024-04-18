//! Cross Site Request Forgery protection.
//!
//! # Send CSRF token to client
//!
//! CSRF token is send as a cookie to the client using the middleware
//! [`SendCsrf`]. The token is send only if the server received a GET request
//! without a valid CSRF token and if the response is a success.
//!
//! The default name of the cookie is `csrftoken` and it can be customized
//! using the enviroment variable `CSRF_COOKIE_NAME`.
//!
//! # Verify CSRF token on server
//!
//! The CSRF token should be send to the server using a custom header, the
//! middleware [`VerifyCsrf`] can be used to check the presence and verify the
//! signature of the sent token.
//!
//! The default name of the header is `x-csrftoken` and it can be customized
//! using the environment variable `CSRF_HEADER_NAME`.

use std::{
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{ready, Context, Poll},
};

use http::header;
use mello_core::csrf::{CsrfKey, CsrfToken};
use pin_project_lite::pin_project;
use tower_layer::Layer;
use tower_service::Service;

/// Create a new `Set-Cookie` header to send the token to the client.
fn create_set_cookie_header(token: CsrfToken, cookie_name: &str) -> http::HeaderValue {
    let cookie_value = token.display().to_string();
    let set_cookie = cookie::Cookie::build((cookie_name, cookie_value))
        .same_site(cookie::SameSite::Strict)
        .secure(true)
        .http_only(false)
        .path("/")
        .build()
        .to_string();

    http::HeaderValue::from_str(&set_cookie).expect("failed to create `Set-Cookie` header")
}

/// Extract the token from the request's cookies.
fn extract_from_cookies(headers: &http::HeaderMap, cookie_name: &str) -> Option<CsrfToken> {
    let cookie = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(|cookie| {
            cookie::Cookie::parse(cookie)
                .ok()
                .filter(|cookie| cookie.name() == cookie_name)
        })
        .next()?;

    cookie.value().parse().ok()
}

/// Extract the token from the request's headers.
fn extract_from_headers(
    headers: &http::HeaderMap,
    header_name: &http::HeaderName,
) -> Option<CsrfToken> {
    headers
        .get_all(header_name)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .filter_map(|header| CsrfToken::from_str(header).ok())
        .next()
}

/// Configuration of [`SendCsrf`] middleware.
#[derive(Debug)]
struct SendCsrfConfig {
    /// Secret key used to sign tokens.
    key: CsrfKey,
    /// Cookie name used to send token to client.
    cookie_name: String,
}

impl SendCsrfConfig {
    /// The environment variable used to set the name of CSRF cookie.
    const CSRF_COOKIE_NAME: &'static str = "CSRF_COOKIE_NAME";
    /// The default name of the cookie.
    const DEFAULT_CSRF_COOKIE_NAME: &'static str = "csrftoken";

    /// Create a new [`SendCsrfConfig`] with the given key.
    fn new(key: &CsrfKey) -> Self {
        Self {
            key: key.clone(),
            cookie_name: Self::default_cookie_name(),
        }
    }

    /// The default value for the cookie name.
    fn default_cookie_name() -> String {
        std::env::var(Self::CSRF_COOKIE_NAME).unwrap_or_else(|err| {
            if let std::env::VarError::NotUnicode(_) = err {
                tracing::warn!("environment variable '{}' ignored", Self::CSRF_COOKIE_NAME);
            }
            Self::DEFAULT_CSRF_COOKIE_NAME.to_string()
        })
    }
}

/// Layer that applies [`SendCsrf`].
#[derive(Clone, Debug)]
pub struct SendCsrfLayer {
    config: Arc<SendCsrfConfig>,
}

impl SendCsrfLayer {
    /// Create a new [`SendCsrfLayer`] with default configuration.
    pub fn new(key: &CsrfKey) -> Self {
        let config = SendCsrfConfig::new(key);
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for SendCsrfLayer {
    type Service = SendCsrf<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SendCsrf {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Middleware that send the CSRF token as cookie.
///
/// This middleware set the cookie with the CSRF token only if the following
/// conditions are met:
///  - the request is a GET request;
///  - the cookie is missing or it is an invalid token;
///  - the response is a success.
#[derive(Clone, Debug)]
pub struct SendCsrf<S> {
    inner: S,
    config: Arc<SendCsrfConfig>,
}

impl<S, Req, Res> Service<http::Request<Req>> for SendCsrf<S>
where
    S: Service<http::Request<Req>, Response = http::Response<Res>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = SendCsrfResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<Req>) -> Self::Future {
        let SendCsrfConfig { cookie_name, key } = self.config.as_ref();
        let token = extract_from_cookies(req.headers(), cookie_name);
        let should_set_cookie = req.method() == http::Method::GET
            && !matches!(token, Some(token) if token.verify(key).is_ok());
        let set_cookie = should_set_cookie
            .then(|| create_set_cookie_header(CsrfToken::generate(key), cookie_name));

        let inner = self.inner.call(req);
        SendCsrfResponseFuture { inner, set_cookie }
    }
}

pin_project! {
    /// Response future for [`SendCsrf`].
    pub struct SendCsrfResponseFuture<F> {
        #[pin]
        inner: F,
        set_cookie: Option<http::HeaderValue>,
    }
}

impl<F, Res, E> Future for SendCsrfResponseFuture<F>
where
    F: Future<Output = Result<http::Response<Res>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut output = ready!(this.inner.poll(cx));
        if let Some(set_cookie) = this.set_cookie.take() {
            if let Ok(res) = &mut output {
                if res.status().is_success() {
                    res.headers_mut().append(header::SET_COOKIE, set_cookie);
                }
            }
        }
        Poll::Ready(output)
    }
}

/// Configuration of [`VerifyCsrf`] middleware.
#[derive(Debug)]
struct VerifyCsrfConfig {
    /// Secret key used to verify tokens.
    key: CsrfKey,
    /// Header containing the token sent by client.
    header_name: http::HeaderName,
}

impl VerifyCsrfConfig {
    /// The environment variable used to set the name of CSRF header.
    const CSRF_HEADER_NAME: &'static str = "CSRF_HEADER_NAME";
    /// The default name of the header.
    const DEFAULT_CSRF_HEADER_NAME: &'static str = "x-csrftoken";

    /// Create a new [`VerifyCsrfConfig`] with the given key.
    fn new(key: &CsrfKey) -> Self {
        Self {
            key: key.clone(),
            header_name: Self::default_header_name(),
        }
    }

    /// The default value for the header name.
    fn default_header_name() -> http::HeaderName {
        let env_header_name = match std::env::var(Self::CSRF_HEADER_NAME) {
            Ok(header_name) => Some(header_name),
            Err(err) => {
                if let std::env::VarError::NotUnicode(_) = err {
                    tracing::warn!("environment variable '{}' ignored", Self::CSRF_HEADER_NAME);
                }
                None
            }
        };

        let header_name =
            env_header_name.and_then(|header_name| {
                match http::HeaderName::from_str(&header_name) {
                    Ok(header_name) => Some(header_name),
                    Err(err) => {
                        tracing::warn!(
                            "environment variable '{}' contains an invalid header name: {err}",
                            Self::CSRF_HEADER_NAME
                        );
                        None
                    }
                }
            });
        header_name.unwrap_or_else(|| http::HeaderName::from_static(Self::DEFAULT_CSRF_HEADER_NAME))
    }
}

/// Layer that applies [`VerifyCsrf`].
#[derive(Clone, Debug)]
pub struct VerifyCsrfLayer {
    config: Arc<VerifyCsrfConfig>,
}

impl VerifyCsrfLayer {
    /// Create a new [`VerifyCsrfLayer`] with default configuration.
    pub fn new(key: &CsrfKey) -> Self {
        let config = VerifyCsrfConfig::new(key);
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for VerifyCsrfLayer {
    type Service = VerifyCsrf<S>;

    fn layer(&self, inner: S) -> Self::Service {
        VerifyCsrf {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Middleware that verify the received CSRF token.
#[derive(Clone, Debug)]
pub struct VerifyCsrf<S> {
    inner: S,
    config: Arc<VerifyCsrfConfig>,
}

impl<S, Req, Res> Service<http::Request<Req>> for VerifyCsrf<S>
where
    S: Service<http::Request<Req>, Response = http::Response<Res>>,
    Res: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = VerifyCsrfResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<Req>) -> Self::Future {
        let VerifyCsrfConfig { key, header_name } = self.config.as_ref();
        match extract_from_headers(req.headers(), header_name) {
            Some(csrf_token) if csrf_token.verify(key).is_ok() => {
                let inner = self.inner.call(req);
                VerifyCsrfResponseFuture::Inner { inner }
            }
            _ => VerifyCsrfResponseFuture::InvalidToken,
        }
    }
}

pin_project! {
    /// Response future for [`VerifyCsrf`].
    #[project = VerifyCsrfResponseFutureProj]
    pub enum VerifyCsrfResponseFuture<F> {
        InvalidToken,
        Inner { #[pin] inner: F },
    }
}

impl<F, Res, E> Future for VerifyCsrfResponseFuture<F>
where
    F: Future<Output = Result<http::Response<Res>, E>>,
    Res: Default,
{
    type Output = Result<http::Response<Res>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this {
            VerifyCsrfResponseFutureProj::InvalidToken => {
                let mut res = http::Response::new(Res::default());
                *res.status_mut() = http::StatusCode::UNAUTHORIZED;
                Poll::Ready(Ok(res))
            }
            VerifyCsrfResponseFutureProj::Inner { inner } => inner.poll(cx),
        }
    }
}
#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use claym::*;
    use tower::{service_fn, ServiceExt};

    use super::*;

    #[tokio::test]
    async fn csrf_cookie_is_sent_if_missing_in_request() {
        let key = CsrfKey::generate();
        let req = http::Request::new(());

        let inner_svc =
            |_: http::Request<()>| async { Ok::<_, Infallible>(http::Response::new(())) };
        let svc = SendCsrfLayer::new(&key).layer(service_fn(inner_svc));
        let res = svc.oneshot(req).await.unwrap();

        let header = assert_some!(res.headers().get(header::SET_COOKIE));
        let header = assert_ok!(header.to_str());
        let cookie = assert_ok!(cookie::Cookie::parse(header));

        // token cannot be http only, it should be accessible from js
        assert_none!(cookie.http_only());

        // token expire with session
        assert_none!(cookie.max_age());
        assert_none!(cookie.expires());

        // check that the cookie is valid
        let token: CsrfToken = assert_ok!(cookie.value().parse());
        assert_ok!(token.verify(&key));
    }

    fn create_csrf_cookie(key: &CsrfKey) -> http::HeaderValue {
        let token = CsrfToken::generate(key);
        let cookie = format!(
            "{}={}",
            SendCsrfConfig::DEFAULT_CSRF_COOKIE_NAME,
            token.display()
        );
        assert_ok!(http::HeaderValue::from_str(&cookie))
    }

    #[tokio::test]
    async fn csrf_cookie_is_sent_if_the_signature_is_not_verified() {
        let key = CsrfKey::generate();
        let mut req = http::Request::new(());
        req.headers_mut()
            .insert(header::COOKIE, create_csrf_cookie(&key));

        // a new key is generated
        let key = CsrfKey::generate();
        let inner_svc =
            |_: http::Request<()>| async { Ok::<_, Infallible>(http::Response::new(())) };
        let svc = SendCsrfLayer::new(&key).layer(service_fn(inner_svc));
        let res = svc.oneshot(req).await.unwrap();

        let header = assert_some!(res.headers().get(header::SET_COOKIE));
        let header = assert_ok!(header.to_str());
        let cookie = assert_ok!(cookie::Cookie::parse(header));

        // token cannot be http only, it should be accessible from js
        assert_none!(cookie.http_only());

        // token expire with session
        assert_none!(cookie.max_age());
        assert_none!(cookie.expires());

        // check that the cookie is valid
        let token: CsrfToken = assert_ok!(cookie.value().parse());
        assert_ok!(token.verify(&key));
    }

    #[tokio::test]
    async fn csrf_cookie_is_not_sent_if_the_signature_is_verified() {
        let key = CsrfKey::generate();
        let mut req = http::Request::new(());
        req.headers_mut()
            .insert(header::COOKIE, create_csrf_cookie(&key));
        let inner_svc =
            |_: http::Request<()>| async { Ok::<_, Infallible>(http::Response::new(())) };
        let svc = SendCsrfLayer::new(&key).layer(service_fn(inner_svc));
        let res = svc.oneshot(req).await.unwrap();

        assert_none!(res.headers().get(header::SET_COOKIE));
    }

    #[tokio::test]
    async fn csrf_cookie_is_sent_only_in_response_of_get_request() {
        let key = CsrfKey::generate();
        let methods = [
            http::Method::CONNECT,
            http::Method::DELETE,
            http::Method::HEAD,
            http::Method::OPTIONS,
            http::Method::PATCH,
            http::Method::POST,
            http::Method::PUT,
            http::Method::TRACE,
        ];
        for method in methods {
            let mut req = http::Request::new(());
            *req.method_mut() = method;
            let inner_svc =
                |_: http::Request<()>| async { Ok::<_, Infallible>(http::Response::new(())) };
            let svc = SendCsrfLayer::new(&key).layer(service_fn(inner_svc));
            let res = svc.oneshot(req).await.unwrap();

            assert_none!(res.headers().get(header::SET_COOKIE));
        }
    }

    #[tokio::test]
    async fn csrf_cookie_is_sent_only_with_success_response() {
        let key = CsrfKey::generate();
        let statuses = [
            http::StatusCode::CONTINUE,
            http::StatusCode::TEMPORARY_REDIRECT,
            http::StatusCode::BAD_REQUEST,
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ];
        for status in statuses {
            let req = http::Request::new(());
            let inner_svc = |_: http::Request<()>| async {
                let mut res = http::Response::new(());
                *res.status_mut() = status;
                Ok::<_, Infallible>(res)
            };
            let svc = SendCsrfLayer::new(&key).layer(service_fn(inner_svc));
            let res = svc.oneshot(req).await.unwrap();

            assert_none!(res.headers().get(header::SET_COOKIE));
        }
    }

    #[tokio::test]
    async fn requests_with_missing_token_are_rejected() {
        let key = CsrfKey::generate();

        let inner_svc =
            |_: http::Request<()>| async { Ok::<_, Infallible>(http::Response::new(())) };

        let svc = VerifyCsrfLayer::new(&key).layer(service_fn(inner_svc));
        let req = http::Request::new(());
        let res = svc.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    fn create_csrf_header(key: &CsrfKey) -> http::HeaderValue {
        let token = CsrfToken::generate(key);
        let token = token.display().to_string();
        assert_ok!(http::HeaderValue::from_str(&token))
    }

    #[tokio::test]
    async fn requests_with_invalid_tokens_are_rejected() {
        let key = CsrfKey::generate();

        let inner_svc =
            |_: http::Request<()>| async { Ok::<_, Infallible>(http::Response::new(())) };

        let svc = VerifyCsrfLayer::new(&key).layer(service_fn(inner_svc));
        let key = CsrfKey::generate();
        let mut req = http::Request::new(());
        req.headers_mut().insert(
            VerifyCsrfConfig::DEFAULT_CSRF_HEADER_NAME,
            create_csrf_header(&key),
        );

        let res = svc.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn requests_with_valid_tokens_are_accepted() {
        let key = CsrfKey::generate();

        let inner_svc =
            |_: http::Request<()>| async { Ok::<_, Infallible>(http::Response::new(())) };

        let svc = VerifyCsrfLayer::new(&key).layer(service_fn(inner_svc));
        let mut req = http::Request::new(());
        req.headers_mut().insert(
            VerifyCsrfConfig::DEFAULT_CSRF_HEADER_NAME,
            create_csrf_header(&key),
        );

        let res = svc.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), http::StatusCode::OK);
    }
}
