mod cli;

use {
    crate::cli::App,
    clap::Parser,
    debrepo::{
        cli::Command,
        exec::maybe_run_helper,
        sandbox::{run_sandbox, HostSandboxExecutor},
    },
    std::{path::PathBuf, process::ExitCode},
    tracing::level_filters::LevelFilter,
    tracing_subscriber::{filter::EnvFilter, fmt},
};

fn init_logging(quiet: bool, debug: u8) {
    let default_level = if quiet {
        LevelFilter::ERROR
    } else {
        match debug {
            0 => LevelFilter::INFO,
            1 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    };
    let trace = debug > 1;
    let filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy()
        .add_directive("polling=warn".parse().unwrap())
        .add_directive("isahc::wire=warn".parse().unwrap());

    let base_format = fmt::format()
        .without_time()
        .with_level(trace)
        .with_target(trace);

    fmt()
        .with_env_filter(filter)
        .event_format(base_format)
        .with_thread_ids(trace) // include thread IDs only in debug mode
        .with_thread_names(trace) // include thread names only in debug mode
        .with_file(trace) // include file path only in debug mode
        .with_line_number(trace) // include line number only in debug mode
        .init();
}

/// Resolve the default cache directory from XDG_CACHE_HOME or HOME/.cache.
fn default_cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        Some(PathBuf::from(xdg))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
    }
    .map(|base| base.join("rdebootstrap"))
}

fn main() -> ExitCode {
    maybe_run_helper(run_sandbox::<HostSandboxExecutor>);
    let mut app = App::parse();
    init_logging(app.quiet, app.debug);
    if !app.no_cache {
        app.cache_dir = app.cache_dir.clone().or_else(default_cache_dir);
    } else {
        app.cache_dir = None;
    }
    match app.cmd.exec(&app) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            println!("{}", err);
            ExitCode::FAILURE
        }
    }
}
