//! Cross Site Request Forgery protection.
//!
//! CSRF protection token are 32 bytes randomly generated token signed using
//! HMAC-BLAKE2. Tokens are sent to the client using cookies and should be
//! sent back to the server using a custom header.
//!
//! # Key generation
//!
//! Each CSRF token is signed using the HMAC-BLAKE2 authentication algorithm
//! to guarantee its authenticity. The key used to sign and verify the token
//! is a sequence of 64 bytes randomly generated using the ChaCha algorithm.
//!
//! From an existing key you can derive other keys using the method `derive`,
//! Argon2 algorithm is used to create the derived key. Each derived key is
//! identified by a tag (a string) and keys generated with the same tag are
//! equal.
//!
//! ```
//! let key = CsrfKey::generate();
//! let derived_key = key.derive("tag");
//! ```
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
    fmt::Display,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{ready, Context, Poll},
};

use base64ct::{Base64Url, Encoding};
use hmac::Mac;
use http::header;
use pin_project_lite::pin_project;
use rand::RngCore;
use tower_layer::Layer;
use tower_service::Service;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng;

/// A typedef of the signature algorithm.
type Hmac = hmac::SimpleHmac<blake2::Blake2s256>;

struct DebugSha256<'a>(&'a [u8]);
impl<'a> std::fmt::Debug for DebugSha256<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::Digest;

        let Self(bytes) = self;

        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        let hash = hasher.finalize();

        f.write_fmt(format_args!("sha256:{:064x?}", hash))
    }
}

/// Private key used to sign and verify tokens.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct CsrfKey([u8; Self::BYTES]);

impl CsrfKey {
    /// The size of the key in bytes.
    const BYTES: usize = 64;

    /// Generate a new random key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; Self::BYTES];
        rng::with_crypto_rng(|rng| rng.fill_bytes(&mut bytes));
        Self(bytes)
    }

    /// Derive a new key, keys with the same tag are equals.
    pub fn derive(&self, tag: &str) -> Self {
        let mut bytes = [0u8; Self::BYTES];
        argon2::Argon2::default()
            .hash_password_into(tag.as_bytes(), &self.0, &mut bytes)
            .expect("failed to generate derived CSRF key");
        Self(bytes)
    }

    /// Returns an object that implements [`Display`].
    ///
    /// [`Display`]: std::fmt::Display
    pub fn display(&self) -> impl Display + '_ {
        DisplayCsrfKey(self)
    }
}

impl std::fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CsrfKey")
            .field(&DebugSha256(&self.0))
            .finish()
    }
}

/// Helper struct for explicitly printing [`CsrfKey`].
struct DisplayCsrfKey<'a>(&'a CsrfKey);

impl<'a> std::fmt::Debug for DisplayCsrfKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0, f)
    }
}

impl<'a> std::fmt::Display for DisplayCsrfKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let CsrfKey(bytes) = self.0;

        const ENCODED_BYTES: usize = (CsrfKey::BYTES * 4 / 3 + 3) & !3;
        let mut buffer = [0u8; ENCODED_BYTES];
        let encoded_key = Base64Url::encode(bytes, &mut buffer).expect("failed to encode CSRF key");

        f.write_str(encoded_key)
    }
}

// CSRF signed token.
struct CsrfToken([u8; Self::BYTES]);

impl CsrfToken {
    /// The number of random bytes.
    const RANDOM_BYTES: usize = 32;
    /// The size of the signature in bytes.
    const SIGNATURE_BYTES: usize = 32;
    /// The size of the token in bytes.
    const BYTES: usize = Self::RANDOM_BYTES + Self::SIGNATURE_BYTES;

    /// Generate a new CSRF random token, signed with the given key.
    fn generate(key: &CsrfKey) -> Self {
        // generate random bytes
        let mut bytes = [0u8; Self::BYTES];
        rng::with_crypto_rng(|rng| rng.fill_bytes(&mut bytes[..Self::RANDOM_BYTES]));

        // token signature
        let mut mac = Hmac::new_from_slice(&key.0).unwrap();
        mac.update(&bytes[..Self::RANDOM_BYTES]);
        let signature = mac.finalize().into_bytes();
        bytes[Self::RANDOM_BYTES..].clone_from_slice(&signature);

        Self(bytes)
    }

    /// Verify the CSRF token with the given key.
    fn verify(&self, key: &CsrfKey) -> Result<(), InvalidCsrfToken> {
        let Self(bytes) = self;

        let mut mac = Hmac::new_from_slice(&key.0).unwrap();
        mac.update(&bytes[..Self::RANDOM_BYTES]);
        mac.verify_slice(&bytes[Self::RANDOM_BYTES..])
            .map_err(|_| InvalidCsrfToken)
    }

    /// Returns an object that implements [`Display`].
    fn display(&self) -> DisplayCsrfToken<'_> {
        DisplayCsrfToken(self)
    }

    /// Create a new `Set-Cookie` header to send the token to the client.
    fn create_set_cookie_header(&self, cookie_name: &str) -> http::HeaderValue {
        let cookie_value = self.display().to_string();
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
    fn extract_from_cookies(headers: &http::HeaderMap, cookie_name: &str) -> Option<Self> {
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
    ) -> Option<Self> {
        headers
            .get_all(header_name)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .filter_map(|header| Self::from_str(header).ok())
            .next()
    }
}

impl std::fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CsrfToken")
            .field(&DebugSha256(&self.0))
            .finish()
    }
}

/// Helper struct for explicitly printing [`CsrfToken`].
struct DisplayCsrfToken<'a>(&'a CsrfToken);

impl<'a> std::fmt::Debug for DisplayCsrfToken<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0, f)
    }
}

impl<'a> std::fmt::Display for DisplayCsrfToken<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let CsrfToken(bytes) = self.0;

        const ENCODED_BYTES: usize = (CsrfToken::BYTES * 4 / 3 + 3) & !3;
        let mut buffer = [0u8; ENCODED_BYTES];
        let encoded_key =
            Base64Url::encode(bytes, &mut buffer).expect("failed to encode CSRF token");

        f.write_str(encoded_key)
    }
}

impl std::str::FromStr for CsrfToken {
    type Err = InvalidCsrfToken;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::BYTES];
        let len = Base64Url::decode(s, &mut bytes)
            .map_err(|err| {
                tracing::error!("Failed to parse CsrfToken: {err}");
                InvalidCsrfToken
            })?
            .len();
        (len == Self::BYTES)
            .then_some(Self(bytes))
            .ok_or(InvalidCsrfToken)
    }
}

/// The error type returned when a token is invalid.
#[derive(Clone, Copy, Debug)]
struct InvalidCsrfToken;

impl std::fmt::Display for InvalidCsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CSRF token is invalid")
    }
}

impl std::error::Error for InvalidCsrfToken {}

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
        let token = CsrfToken::extract_from_cookies(req.headers(), cookie_name);
        let should_set_cookie = req.method() == http::Method::GET
            && !matches!(token, Some(token) if token.verify(key).is_ok());
        let set_cookie = should_set_cookie
            .then(|| CsrfToken::generate(key).create_set_cookie_header(cookie_name));

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
        match CsrfToken::extract_from_headers(req.headers(), header_name) {
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

    #[test]
    fn csrf_token_generation_and_verification() {
        let key = CsrfKey::generate();
        let token = CsrfToken::generate(&key);
        assert_ok!(token.verify(&key));

        let another_key = CsrfKey::generate();
        assert_err!(token.verify(&another_key));
    }

    #[test]
    fn csrf_derived_keys_as_distinct() {
        let key = CsrfKey::generate();
        let signup_key = key.derive("signup");
        let token = CsrfToken::generate(&signup_key);

        let new_signup_key = key.derive("signup");
        assert_ok!(token.verify(&new_signup_key));

        let signin_key = key.derive("signin");
        assert_err!(token.verify(&signin_key));
    }

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
        assert_ok!(http::HeaderValue::from_str(&token.display().to_string()))
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
