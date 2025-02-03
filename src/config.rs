//! Module for handling configuration settings for HyperHook.

use config::Config;
use once_cell::sync::Lazy;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct HyperhookConfig {
    mode: String,
    tracing: TraceOptions,
}

#[derive(Debug, Deserialize)]
struct TraceOptions {
    libs: Vec<String>,
}

/// Not used for now. Could be used to dump core in reproduction mode or e.g. backtrace in trace mode
pub enum HyerhookMode {
    /// Default operation
    Fuzz,
    /// Reproduction run
    Reproduce,
    /// Trace run
    Trace,
}

static CONFIG: Lazy<HyperhookConfig> = Lazy::new(|| {
    let settings = Config::builder()
        .add_source(config::File::with_name("config.yaml"))
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .add_source(config::Environment::with_prefix("HYPERHOOK"))
        .build()
        .unwrap();
    settings.try_deserialize::<HyperhookConfig>().unwrap()
});

/// Returns a `HyerhookMode` enum value, based on the mode specified in the configuration.
pub fn get_hyperhook_mode() -> HyerhookMode {
    let mode = CONFIG.mode.as_str();
    match mode {
        "fuzz" => HyerhookMode::Fuzz,
        "reproduce" => HyerhookMode::Reproduce,
        "trace" => HyerhookMode::Trace,
        _ => panic!("Invalid mode set: {}", mode),
    }
}

/// Returns a vector of strings containing the library names to be traced during execution.
pub fn get_pt_trace_libs() -> Vec<String> {
    CONFIG.tracing.libs.to_vec()
}
