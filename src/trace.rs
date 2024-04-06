//! Tracing initialization of writer for [`tracing`] events.
//!
//! [`tracing`]: https://docs.rs/tracing/

use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::Directive,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Trace configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TraceConfig {
    /// Where to write events.
    pub output: TraceOutput,
    /// The minimum event level to emit.
    pub level: TraceLevel,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            output: TraceOutput::Stderr,
            level: TraceLevel::Info,
        }
    }
}

/// Verbosity level.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TraceLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Define where to write the logs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TraceOutput {
    /// Standard error.
    Stderr,
    /// Standard output.
    Stdout,
    /// No output
    Discard,
    /// Write to the given file.
    File(PathBuf),
}

/// Initialize event writer.
///
/// Setup the event writer with the given configuration. The level filter can be
/// changed at runtime using the enviroment variable `RUST_LOG`.
pub fn init(config: &TraceConfig) -> std::io::Result<()> {
    static TRACE: OnceCell<Trace> = OnceCell::new();
    TRACE.get_or_try_init(|| Trace::new(config))?;

    Ok(())
}

/// Trace state
#[allow(dead_code)]
struct Trace {
    appender_guard: WorkerGuard,
}

impl Trace {
    fn new(config: &TraceConfig) -> std::io::Result<Self> {
        let level = match config.level {
            TraceLevel::Trace => Level::TRACE,
            TraceLevel::Debug => Level::DEBUG,
            TraceLevel::Info => Level::INFO,
            TraceLevel::Warn => Level::WARN,
            TraceLevel::Error => Level::ERROR,
        };

        let writer: Box<dyn Write + Send> = match &config.output {
            TraceOutput::Stderr => Box::new(std::io::stderr()),
            TraceOutput::Stdout => Box::new(std::io::stdout()),
            TraceOutput::Discard => Box::new(std::io::sink()),
            TraceOutput::File(path) => {
                let ofile = std::fs::File::create(path)?;
                Box::new(BufWriter::new(ofile))
            }
        };

        let (writer, guard) = tracing_appender::non_blocking(writer);

        let env_filter = EnvFilter::builder()
            .with_default_directive(Directive::from(level))
            .with_env_var(EnvFilter::DEFAULT_ENV)
            .from_env_lossy();
        let fmt_layer = fmt::layer()
            .with_writer(writer)
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_line_number(true)
            .with_file(true);

        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(env_filter)
            .try_init()
            .expect("failed to set global default subscriber");

        Ok(Self {
            appender_guard: guard,
        })
    }
}
