//! Simple HTTP reverse proxy tower service.
//!
//! The implementation is based on Go's [`httputil.ReverseProxy`].
//!
//! [`httputil.ReverseProxy`]: https://go.dev/src/net/http/httputil/reverseproxy.go

use std::{
    convert::Infallible,
    error::Error as StdError,
    future::{poll_fn, Future},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use bytes::BytesMut;
use http::header;
use hyper::{
    body::{Body as HttpBody, Frame, SizeHint},
    client::conn::http1,
    upgrade::OnUpgrade,
};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use slab::Slab;
use tokio::{
    io::copy_bidirectional,
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};

pin_project! {
    /// Response body of [`ReverseProxy`].
    pub struct Body {
        #[pin]
        body: Option<hyper::body::Incoming>,
    }
}

impl Body {
    /// Create a new empty body.
    fn empty() -> Self {
        Self { body: None }
    }

    /// Returns the contained [`hyper`] body.
    ///
    /// [`hyper`]: https://docs.rs/hyper/latest/hyper/body/struct.Incoming.html
    #[inline]
    pub fn unwrap(self) -> Option<hyper::body::Incoming> {
        self.body
    }
}

impl HttpBody for Body {
    type Data = <hyper::body::Incoming as HttpBody>::Data;
    type Error = <hyper::body::Incoming as HttpBody>::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.body.as_pin_mut() {
            Some(body) => body.poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.body
            .as_ref()
            .map(HttpBody::is_end_stream)
            .unwrap_or_else(|| true)
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.body
            .as_ref()
            .map(HttpBody::size_hint)
            .unwrap_or_else(|| SizeHint::with_exact(0))
    }
}

/// Remote peer address, intended to be used as an extension.
#[derive(Clone, Debug)]
pub struct RemoteAddr(pub SocketAddr);

/// HTTP reverse proxy.
pub struct ReverseProxy<Req> {
    pool: Arc<Pool<Req>>,
}

impl<Req> Clone for ReverseProxy<Req> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

impl<Req> ReverseProxy<Req> {
    /// Forward all HTTP requests to the given address.
    pub fn new<A: Into<SocketAddr>>(addr: A) -> Self {
        let capacity = 4 * num_cpus::get_physical();
        Self::with_capacity(addr, capacity)
    }

    /// Create a new [`ReverseProxy`] with the given capacity.
    pub fn with_capacity<A: Into<SocketAddr>>(addr: A, capacity: usize) -> Self {
        let pool = Pool::new(addr.into(), capacity);
        Self {
            pool: Arc::new(pool),
        }
    }
}

/// Response future for [`ReverseProxy`].
pub type ReverseProxyResponseFuture =
    Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;

impl<Req> tower_service::Service<http::Request<Req>> for ReverseProxy<Req>
where
    Req: HttpBody + Send + 'static,
    Req::Data: Send,
    Req::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = ReverseProxyResponseFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Req>) -> Self::Future {
        let pool = self.pool.clone();
        Box::pin(async move {
            Ok(pool.forward_request(req).await.unwrap_or_else(|err| {
                tracing::error!("bad gateway: {err}");
                build_bat_gateway_response()
            }))
        })
    }
}

impl<Req> hyper::service::Service<http::Request<Req>> for ReverseProxy<Req>
where
    Req: HttpBody + Send + 'static,
    Req::Data: Send,
    Req::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = ReverseProxyResponseFuture;

    fn call(&self, req: http::Request<Req>) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move {
            poll_fn(|cx| tower_service::Service::poll_ready(&mut this, cx))
                .await
                .map(|_| tower_service::Service::call(&mut this, req))?
                .await
        })
    }
}

/// Build the bad gateway response.
fn build_bat_gateway_response() -> http::Response<Body> {
    let mut response = http::Response::new(Body::empty());
    *response.status_mut() = http::StatusCode::BAD_GATEWAY;
    response
}

/// Possible errors from [`Pool`].
#[derive(Debug)]
enum PoolError {
    Io(std::io::Error),
    Hyper(hyper::Error),
}

impl std::fmt::Display for PoolError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => std::fmt::Display::fmt(err, f),
            Self::Hyper(err) => std::fmt::Display::fmt(err, f),
        }
    }
}

impl From<hyper::Error> for PoolError {
    #[inline(always)]
    fn from(err: hyper::Error) -> Self {
        Self::Hyper(err)
    }
}

impl From<std::io::Error> for PoolError {
    #[inline(always)]
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// A pool used to recycle existing connection to a given address.
struct Pool<Req> {
    addr: SocketAddr,
    semaphore: Arc<Semaphore>,
    slots: Mutex<Slab<SendRequest<Req>>>,
}

type SendRequest<Req> = http1::SendRequest<Req>;

impl<Req> Pool<Req> {
    /// Create a new pool of connection with the given capacity.
    fn new(addr: SocketAddr, capacity: usize) -> Self {
        let semaphore = Semaphore::new(capacity);
        let slots = Slab::with_capacity(capacity);
        Self {
            addr,
            semaphore: Arc::new(semaphore),
            slots: Mutex::new(slots),
        }
    }

    /// Put the connection back in the pool.
    fn return_connection(&self, connection: SendRequest<Req>) {
        let mut slots = self.slots.lock();
        slots.vacant_entry().insert(connection);
    }
}

impl<Req> Pool<Req>
where
    Req: HttpBody + Send + 'static,
    Req::Data: Send,
    Req::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    /// Connect or recycle the connection
    async fn connect(self: &Arc<Self>) -> Result<Connection<Req>, PoolError> {
        // avoid to exceed the pool capacity
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();

        // try to recyle an existing connection, if the connection present in
        // the pool is closed then it is dropped
        let connection = {
            let mut slots = self.slots.lock();
            let key = slots.iter().next().map(|(key, _)| key);
            key.map(|key| slots.remove(key))
                .filter(|conn| !conn.is_closed())
        };

        let connection = match connection {
            Some(connection) if !connection.is_closed() => connection,
            _ => {
                let stream = TcpStream::connect(self.addr).await?;
                let io = TokioIo::new(stream);
                let (send_request, conn) = http1::handshake(io).await.unwrap();
                tokio::spawn(async move {
                    if let Err(err) = conn.with_upgrades().await {
                        tracing::error!("connection failed: {err}");
                    }
                });
                send_request
            }
        };

        let pool = Arc::downgrade(self);

        Ok(Connection {
            permit,
            connection: Some(connection),
            pool,
        })
    }

    /// Forward the HTTP request
    async fn forward_request(
        self: Arc<Self>,
        mut req: http::Request<Req>,
    ) -> Result<http::Response<Body>, PoolError> {
        // prepare the request removing hop-by-hop headers and managing the upgrade requests
        let req_upgrade_type = request_upgrade_type(req.headers());
        remove_hop_by_hop_headers(req.headers_mut());
        if let Some(upgrade) = req_upgrade_type {
            set_upgrade_headers(req.headers_mut(), upgrade);
        }
        let remote_addr = req.extensions_mut().remove::<RemoteAddr>();
        set_x_forwarded(req.headers_mut(), remote_addr);

        let req_on_upgrade = hyper::upgrade::on(&mut req);

        let mut connection = self.connect().await?;
        let mut res = connection.send_request(req).await?;

        // handle 101 switching protocol
        if res.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            let res_on_upgrade = hyper::upgrade::on(&mut res);
            tokio::spawn(async move {
                if let Err(err) = pipe_upgraded_connections(req_on_upgrade, res_on_upgrade).await {
                    tracing::error!("failed to pipe upgraded connections: {err}");
                }
            });
            return Ok(res);
        }

        remove_hop_by_hop_headers(res.headers_mut());
        Ok(res)
    }
}

fn request_upgrade_type(headers: &http::HeaderMap) -> Option<http::HeaderValue> {
    let is_connection_upgrade = headers
        .get(header::CONNECTION)
        .map(|header| header_value_contains_token(header, "Upgrade"))
        .unwrap_or_default();

    if is_connection_upgrade {
        return headers.get(header::UPGRADE).cloned();
    }
    None
}

fn set_upgrade_headers(headers: &mut http::HeaderMap, upgrade: http::HeaderValue) {
    headers.insert(
        header::CONNECTION,
        http::HeaderValue::from_static("Upgrade"),
    );
    headers.insert(header::UPGRADE, upgrade);
}

/// Reports whether the header value contains the token among its comma-separated tokens.
fn header_value_contains_token(header: &http::HeaderValue, token: &str) -> bool {
    header
        .as_bytes()
        .split(|&c| c == b',')
        .map(trim_ascii_whitespace)
        .any(|value| value == token.as_bytes())
}

/// Returns a byte slice with trailing and leading ASCII whitespace bytes removed.
fn trim_ascii_whitespace(value: &[u8]) -> &[u8] {
    let mut bytes = value;
    while let [head, tail @ ..] = bytes {
        if head.is_ascii_whitespace() {
            bytes = tail;
        } else {
            break;
        }
    }
    while let [init @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = init;
        } else {
            break;
        }
    }
    bytes
}

/// Set the `X-Forwarded-*` headers.
fn set_x_forwarded(headers: &mut http::HeaderMap, remote_addr: Option<RemoteAddr>) {
    const X_FORWARDED_FOR: http::HeaderName = http::HeaderName::from_static("x-forwarded-for");
    const X_FORWARDED_HOST: http::HeaderName = http::HeaderName::from_static("x-forwarded-host");
    const X_FORWARDED_PROTO: http::HeaderName = http::HeaderName::from_static("x-forwarded-proto");

    const HTTP: http::HeaderValue = http::HeaderValue::from_static("http");

    if let Some(remote_addr) = remote_addr {
        let ip = remote_addr.0.ip().to_string();

        match headers.entry(X_FORWARDED_FOR) {
            header::Entry::Occupied(mut entry) => {
                let header_value = entry
                    .iter()
                    .flat_map(|value| value.as_bytes().split(|&c| c == b','))
                    .chain([ip.as_bytes()])
                    .fold(BytesMut::new(), |mut buffer, value| {
                        if !buffer.is_empty() {
                            buffer.extend_from_slice(b", ");
                            buffer.extend_from_slice(value);
                        }
                        buffer
                    })
                    .freeze();
                let header_value = http::HeaderValue::from_bytes(&header_value).unwrap();
                entry.insert(header_value);
            }
            header::Entry::Vacant(entry) => {
                let value = http::HeaderValue::from_str(&ip).unwrap();
                entry.insert(value);
            }
        }
    } else {
        if let header::Entry::Occupied(entry) = headers.entry(X_FORWARDED_FOR) {
            entry.remove_entry_mult();
        }
    }

    if let Some(host) = headers.get(header::HOST).cloned() {
        headers.insert(X_FORWARDED_HOST, host);
    }
    headers.insert(X_FORWARDED_PROTO, HTTP);
}

/// Remove hop-by-hop headers
fn remove_hop_by_hop_headers(headers: &mut http::HeaderMap) {
    let headers_to_remove: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|header| header.as_bytes().split(|&c| c == b','))
        .filter_map(|bytes| http::HeaderName::from_bytes(trim_ascii_whitespace(bytes)).ok())
        .collect();
    for header_name in headers_to_remove {
        headers.remove(header_name);
    }

    const HOP_HEADERS: [http::HeaderName; 9] = [
        header::CONNECTION,
        http::HeaderName::from_static("proxy-connection"),
        http::HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ];
    for header_name in HOP_HEADERS {
        headers.remove(header_name);
    }
}

/// Pipes upgraded connections
async fn pipe_upgraded_connections(
    req_on_upgrade: OnUpgrade,
    res_on_upgrade: OnUpgrade,
) -> Result<(), PoolError> {
    let req_upgraded = req_on_upgrade.await?;
    let res_upgraded = res_on_upgrade.await?;

    let mut req_io = TokioIo::new(req_upgraded);
    let mut res_io = TokioIo::new(res_upgraded);
    copy_bidirectional(&mut req_io, &mut res_io).await.unwrap();

    Ok(())
}

struct Connection<Req> {
    #[allow(dead_code)]
    permit: OwnedSemaphorePermit,
    connection: Option<SendRequest<Req>>,
    pool: Weak<Pool<Req>>,
}

impl<Req> Connection<Req>
where
    Req: HttpBody + 'static,
{
    /// Send an HTTP request
    async fn send_request(
        &mut self,
        req: http::Request<Req>,
    ) -> Result<http::Response<Body>, PoolError> {
        let connection = self.connection.as_mut().unwrap();
        connection.ready().await?;
        let response = connection.send_request(req).await?;

        Ok(response.map(|body| Body { body: Some(body) }))
    }
}

impl<Req> Drop for Connection<Req> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            if let Some(connection) = self.connection.take() {
                pool.return_connection(connection)
            }
        }
    }
}
