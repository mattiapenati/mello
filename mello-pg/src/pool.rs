//! Postgres database utilies

use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Weak},
};

use parking_lot::Mutex;
use slab::Slab;
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio_postgres::{config::SslMode, Config as PgConfig, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

/// An error while communicating with the Postgres server.
pub type PgError = tokio_postgres::Error;

/// A pool of connection to a database.
#[derive(Clone)]
pub struct PgPool {
    inner: Arc<Inner>,
}

struct Inner {
    pg_config: PgConfig,
    semaphore: Semaphore,
    slots: Mutex<Slab<tokio_postgres::Client>>,
}

impl PgPool {
    /// Create a new [`PgPool`] with the given configuration.
    pub fn new(config: &str) -> Result<Self, PgError> {
        let capacity = 4 * num_cpus::get_physical();
        Self::with_capacity(config, capacity)
    }

    /// Create a new [`PgPool`] with the given capacity.
    pub fn with_capacity(config: &str, capacity: usize) -> Result<Self, PgError> {
        let inner = Inner {
            pg_config: config.parse()?,
            semaphore: Semaphore::new(capacity),
            slots: Mutex::new(Slab::new()),
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Creaete a new connection to the database.
    pub async fn connect(&self) -> Result<PgClient<'_>, PgError> {
        let Inner {
            pg_config,
            semaphore,
            slots,
        } = self.inner.as_ref();

        let permit = semaphore.acquire().await.unwrap();
        let pg_client = {
            let mut slots = slots.lock();
            let key = slots.iter().next().map(|(key, _)| key);
            key.map(|key| slots.remove(key))
                .filter(|conn| conn.is_closed())
        };

        let pg_client = match pg_client {
            Some(pg_client) => pg_client,
            None => match pg_config.get_ssl_mode() {
                SslMode::Disable => {
                    let (pg_client, conn) = pg_config.connect(NoTls).await?;
                    tokio::spawn(conn);
                    pg_client
                }
                SslMode::Require => {
                    let tls = Self::make_rustls_connect();
                    let (pg_client, conn) = pg_config.connect(tls).await?;
                    tokio::spawn(conn);
                    pg_client
                }
                _ => {
                    let tls = Self::make_rustls_connect();
                    match pg_config.connect(tls).await {
                        Ok((pg_client, conn)) => {
                            tokio::spawn(conn);
                            pg_client
                        }
                        Err(err) => {
                            tracing::warn!("Failed to connect to Postgres with TLS: {err}");
                            let tls = NoTls;
                            let (pg_client, conn) = pg_config.connect(tls).await?;
                            tokio::spawn(conn);
                            pg_client
                        }
                    }
                }
            },
        };

        let inner = Arc::downgrade(&self.inner);

        Ok(PgClient {
            permit,
            pg_client: Some(pg_client),
            inner,
        })
    }

    fn make_rustls_connect() -> MakeRustlsConnect {
        let mut roots = rustls::RootCertStore::empty();
        let certificates =
            rustls_native_certs::load_native_certs().expect("Failed to load platform certificates");
        for cert in certificates {
            roots.add(cert).unwrap();
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        MakeRustlsConnect::new(config)
    }
}

/// A smart pointer to a connection.
pub struct PgClient<'a> {
    #[allow(dead_code)]
    permit: SemaphorePermit<'a>,
    pg_client: Option<tokio_postgres::Client>,
    inner: Weak<Inner>,
}

impl<'a> Deref for PgClient<'a> {
    type Target = tokio_postgres::Client;
    fn deref(&self) -> &Self::Target {
        self.pg_client.as_ref().unwrap()
    }
}

impl<'a> DerefMut for PgClient<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.pg_client.as_mut().unwrap()
    }
}

impl<'a> Drop for PgClient<'a> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            if let Some(pg_client) = self.pg_client.take() {
                let mut slots = inner.slots.lock();
                slots.vacant_entry().insert(pg_client);
            }
        }
    }
}
