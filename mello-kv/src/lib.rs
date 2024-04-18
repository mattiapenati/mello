//! An implementation of a key-value storage based on SQLite.

use std::{
    fmt::Display,
    path::{Path, PathBuf},
    sync::Arc,
};

use parking_lot::{Mutex, MutexGuard};
use rusqlite::OptionalExtension;
use serde::{de::DeserializeOwned, Serialize};
use thread_local::ThreadLocal;

mod rand;

/// Connection options.
enum ConnectionOptions {
    Memory(String),
    File(PathBuf),
}

impl ConnectionOptions {
    fn connect(&self, flags: rusqlite::OpenFlags) -> rusqlite::Result<rusqlite::Connection> {
        let conn = match self {
            Self::Memory(name) => rusqlite::Connection::open_with_flags(
                format!("file:{name}?mode=memory&cache=shared"),
                flags,
            )?,
            Self::File(path) => rusqlite::Connection::open_with_flags(path, flags)?,
        };

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "temp_store", "memory")?;

        Ok(conn)
    }
}

/// Possible errors from [`KVStorage`].
pub enum Error {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl From<rusqlite::Error> for Error {
    #[inline(always)]
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

impl From<serde_json::Error> for Error {
    #[inline(always)]
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl std::fmt::Debug for Error {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(err) => std::fmt::Debug::fmt(err, f),
            Self::Json(err) => std::fmt::Debug::fmt(err, f),
        }
    }
}

impl std::fmt::Display for Error {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(err) => std::fmt::Display::fmt(err, f),
            Self::Json(err) => std::fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for Error {
    #[inline(always)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(err) => std::error::Error::source(err),
            Self::Json(err) => std::error::Error::source(err),
        }
    }
}

/// A type definition of the result returned by [`KVStorage`]
pub type Result<T> = std::result::Result<T, Error>;

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

impl std::fmt::Debug for KVStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("KVStorage");
        match &self.inner.options {
            ConnectionOptions::Memory(name) => fmt.field("memory", name),
            ConnectionOptions::File(path) => fmt.field("file", path),
        }
        .finish()
    }
}

impl KVStorage {
    /// Create a new persistent key-value storage on disk.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let options = ConnectionOptions::File(path);
        Self::open_with_options(options)
    }

    /// Create a new in-memory key-value storage.
    pub fn in_memory() -> Result<Self> {
        let name = generate_random_name();
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
    pub fn write(&self) -> WriteConn<'_> {
        let conn = self.inner.write.lock();
        WriteConn { conn }
    }

    /// Get a connection with read-only permission.
    pub fn read(&self) -> Result<ReadConn<'_>> {
        let conn = self.inner.read.get_or_try(|| {
            let flags = read_flags();
            self.inner.options.connect(flags)
        })?;
        Ok(ReadConn { conn })
    }
}

/// RAII structure used to release a connection with exclusive write permission.
pub struct WriteConn<'a> {
    conn: MutexGuard<'a, rusqlite::Connection>,
}

impl<'a> WriteConn<'a> {
    /// Get the value of key.
    pub fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Display,
        V: DeserializeOwned,
    {
        get(&self.conn, &key.to_string())
    }

    /// Check if the key exists.
    #[inline(always)]
    pub fn has<K>(&self, key: K) -> Result<bool>
    where
        K: Display,
    {
        has(&self.conn, &key.to_string())
    }

    /// Set the value of key.
    pub fn set<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Display,
        V: ?Sized + Serialize,
    {
        set(&self.conn, &key.to_string(), value)
    }

    /// Remove the specified key.
    pub fn del<K>(&self, key: K) -> Result<()>
    where
        K: Display,
    {
        del(&self.conn, &key.to_string())
    }

    /// Remove the specified key and return the stored value.
    pub fn extract<K, V>(&mut self, key: K) -> Result<Option<V>>
    where
        K: Display,
        V: DeserializeOwned,
    {
        let tx = self.transaction()?;
        let value = tx.extract(key)?;
        tx.commit()?;
        Ok(value)
    }

    /// Begin a new transaction.
    pub fn transaction(&mut self) -> Result<WriteTx<'_>> {
        let behavior = rusqlite::TransactionBehavior::Immediate;
        let tx = self.conn.transaction_with_behavior(behavior)?;
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
        get(&self.tx, &key.to_string())
    }

    /// Check if the key exists.
    #[inline(always)]
    pub fn has<K>(&self, key: K) -> Result<bool>
    where
        K: Display,
    {
        has(&self.tx, &key.to_string())
    }

    /// Set the value of key.
    pub fn set<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Display,
        V: ?Sized + Serialize,
    {
        set(&self.tx, &key.to_string(), value)
    }

    /// Remove the specified key.
    pub fn del<K>(&self, key: K) -> Result<()>
    where
        K: Display,
    {
        del(&self.tx, &key.to_string())
    }

    /// Remove the specified key and return the stored value.
    pub fn extract<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Display,
        V: DeserializeOwned,
    {
        let key = key.to_string();
        let value = self.get(&key)?;
        self.del(&key)?;
        Ok(value)
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
pub struct ReadConn<'a> {
    conn: &'a rusqlite::Connection,
}

impl<'a> ReadConn<'a> {
    /// Get the value of key.
    #[inline(always)]
    pub fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Display,
        V: DeserializeOwned,
    {
        get(self.conn, &key.to_string())
    }

    /// Check if the key exists.
    #[inline(always)]
    pub fn has<K>(&self, key: K) -> Result<bool>
    where
        K: Display,
    {
        has(self.conn, &key.to_string())
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
fn get<V>(conn: &rusqlite::Connection, key: &str) -> Result<Option<V>>
where
    V: DeserializeOwned,
{
    conn.query_row("SELECT value FROM kv WHERE KEY = ?1", (key,), |row| {
        row.get::<_, String>("value")
    })
    .optional()?
    .map(|value| serde_json::from_str::<V>(&value))
    .transpose()
    .map_err(Into::into)
}

/// Check if the key exists.
fn has(conn: &rusqlite::Connection, key: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT value from kv WHERE KEY = ?1) AS has",
        (key,),
        |row| row.get::<_, bool>("has"),
    )
    .map_err(Into::into)
}

/// Set the value of key.
fn set<V>(conn: &rusqlite::Connection, key: &str, value: &V) -> Result<()>
where
    V: ?Sized + Serialize,
{
    let serialized_value = serde_json::to_string(value)?;
    conn.execute(
        "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
        (key, serialized_value),
    )?;
    Ok(())
}

/// Remove the specified key.
fn del(conn: &rusqlite::Connection, key: &str) -> Result<()> {
    conn.execute("DELETE FROM kv WHERE key = ?1", (key,))?;
    Ok(())
}

/// Generate a new random name for in-memory database.
fn generate_random_name() -> String {
    let a = rand::random();
    let b = rand::random();
    format!("{a:016x}-{b:016x}")
}

#[cfg(test)]
mod tests {
    use claym::*;

    use super::*;

    #[test]
    fn set_and_get() {
        let kv = assert_ok!(KVStorage::in_memory());
        let wconn = kv.write();
        let rconn = assert_ok!(kv.read());

        let value: Option<usize> = assert_ok!(rconn.get("key"));
        assert_none!(value);

        assert_ok!(wconn.set("key", &1_usize));

        let value: Option<usize> = assert_ok!(rconn.get("key"));
        assert_some_eq!(value, 1);
    }

    #[test]
    fn delete() {
        let kv = assert_ok!(KVStorage::in_memory());
        let wconn = kv.write();
        let rconn = assert_ok!(kv.read());

        assert_ok!(wconn.set("key", &1_usize));

        let value: Option<usize> = assert_ok!(rconn.get("key"));
        assert_some_eq!(value, 1);

        assert_ok!(wconn.del("key"));

        let value: Option<usize> = assert_ok!(rconn.get("key"));
        assert_none!(value);
    }

    #[test]
    fn extract() {
        let kv = assert_ok!(KVStorage::in_memory());
        let mut wconn = kv.write();

        assert_ok!(wconn.set("key", &1_usize));

        let value: Option<usize> = assert_ok!(wconn.extract("key"));
        assert_some_eq!(value, 1);

        let value: Option<usize> = assert_ok!(wconn.extract("key"));
        assert_none!(value);
    }
}
