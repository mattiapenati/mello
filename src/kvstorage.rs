//! A simple implementation of a key-value storage based on SQLite.

use std::{
    fmt::Display,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use parking_lot::{Mutex, MutexGuard};
use rusqlite::OptionalExtension;
use serde::{de::DeserializeOwned, Serialize};
use thread_local::ThreadLocal;

/// Connection options.
enum ConnectionOptions {
    Memory(String),
    File(PathBuf),
}

impl ConnectionOptions {
    fn connect(&self, flags: rusqlite::OpenFlags) -> rusqlite::Result<rusqlite::Connection> {
        match self {
            Self::Memory(name) => rusqlite::Connection::open_with_flags(
                format!("file:{name}?mode=memory&cache=shared"),
                flags,
            ),
            Self::File(path) => rusqlite::Connection::open_with_flags(path, flags),
        }
    }
}

/// A simple implementation of a key-value storage based on SQLite.
///
/// The storage keep only connection to the database with write permission and
/// one connection per thread with read-only permission.
#[derive(Clone)]
pub struct KVStorage {
    inner: Arc<Inner>,
}

struct Inner {
    /// Connection options.
    options: ConnectionOptions,
    /// A connection with read and write permissions.
    write: Mutex<rusqlite::Connection>,
    /// A connection with read-only permissions.
    read: ThreadLocal<rusqlite::Connection>,
}

impl KVStorage {
    /// Create a new persistent key-value storage on disk.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let options = ConnectionOptions::File(path);
        Self::open_with_options(options)
    }

    /// Create a new in-memory key-value storage.
    pub fn in_memory(name: &str) -> Result<Self> {
        let name = name.to_string();
        let options = ConnectionOptions::Memory(name);
        Self::open_with_options(options)
    }

    fn open_with_options(options: ConnectionOptions) -> Result<Self> {
        let flags = write_flags();
        let mut write = options.connect(flags)?;
        init(&mut write)?;

        let read = ThreadLocal::new();

        let inner = Inner {
            options,
            write: Mutex::new(write),
            read,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Get a connection with exclusive write permission.
    pub fn write(&self) -> WriteGuard<'_> {
        let conn = self.inner.write.lock();
        WriteGuard { conn }
    }

    /// Get a connection with read-only permission.
    pub fn read(&self) -> Result<ReadGuard<'_>> {
        let conn = self.inner.read.get_or_try(|| {
            let flags = read_flags();
            self.inner.options.connect(flags)
        })?;
        Ok(ReadGuard { conn })
    }
}

/// RAII structure used to release a connection with exclusive write permission.
pub struct WriteGuard<'a> {
    conn: MutexGuard<'a, rusqlite::Connection>,
}

impl<'a> WriteGuard<'a> {
    /// Get the value of key.
    pub fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Display,
        V: DeserializeOwned,
    {
        get(&self.conn, key)
    }

    /// Set the value of key.
    pub fn set<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Display,
        V: Serialize,
    {
        set(&self.conn, key, value)
    }

    /// Begin a new transaction.
    pub fn transaction(&mut self) -> Result<WriteTx<'_>> {
        let tx = self.conn.transaction()?;
        Ok(WriteTx { tx })
    }
}

/// RAII structure used to roll backs transaction on failures.
pub struct WriteTx<'a> {
    tx: rusqlite::Transaction<'a>,
}

impl<'a> WriteTx<'a> {
    /// Get the value of key.
    pub fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Display,
        V: DeserializeOwned,
    {
        get(&self.tx, key)
    }

    /// Set the value of key.
    pub fn set<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Display,
        V: Serialize,
    {
        set(&self.tx, key, value)
    }

    /// Consumes and commits the transaction.
    pub fn commit(self) -> Result<()> {
        self.tx.commit().map_err(Into::into)
    }

    /// Consumes and roll backs the transaction.
    pub fn rollback(self) -> Result<()> {
        self.tx.rollback().map_err(Into::into)
    }
}

/// RAII structure used to release a thread-local connection with read-only permission.
pub struct ReadGuard<'a> {
    conn: &'a rusqlite::Connection,
}

impl<'a> ReadGuard<'a> {
    /// Get the value of key.
    #[inline(always)]
    pub fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Display,
        V: DeserializeOwned,
    {
        get(self.conn, key)
    }
}

/// Default flags for connection with write permission.
fn write_flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
}

/// Default flags for connection with read-only permission.
fn read_flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
}

/// Initialize the database with the required tables.
fn init(conn: &mut rusqlite::Connection) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        (),
    )?;
    tx.commit()?;
    Ok(())
}

/// Get the value of key.
fn get<K, V>(conn: &rusqlite::Connection, key: K) -> Result<Option<V>>
where
    K: Display,
    V: DeserializeOwned,
{
    conn.query_row(
        "SELECT value FROM kv WHERE KEY = ?1",
        (key.to_string(),),
        |row| row.get::<_, String>("value"),
    )
    .optional()?
    .map(|value| serde_json::from_str::<V>(&value))
    .transpose()
    .map_err(Into::into)
}

/// Set the value of key.
fn set<K, V>(conn: &rusqlite::Connection, key: K, value: &V) -> Result<()>
where
    K: Display,
    V: Serialize,
{
    let serialized_value = serde_json::to_string(value)?;
    conn.execute(
        "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
        (key.to_string(), serialized_value),
    )?;
    Ok(())
}
