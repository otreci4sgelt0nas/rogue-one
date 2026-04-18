//! main.rs — Tokio runtime entry point for the sniper bot.
//!
//! # Runtime configuration
//!
//! Uses the tokio multi-thread scheduler (work-stealing, N threads = CPU count).
//! On the AWS c7g.large (2 vCPUs / 2 Graviton cores), this means 2 worker
//! threads — one naturally "owned" by the Binance WS hot path, the other by
//! the Polymarket WS + SituationRoom background tasks.
//!
//! # Startup sequence
//!
//! 1. Load tracing subscriber (structured JSON or pretty depending on env).
//! 2. Force CONFIG initialisation (panics early on bad .env rather than mid-trade).
//! 3. Log the full config summary (redacts private key).
//! 4. Construct `SniperBrain` and await `brain.start()`.
//! 5. Block on `tokio::signal` — bot runs until SIGINT (Ctrl+C) or SIGTERM.
//! 6. Graceful shutdown: log summary, flush tracing, exit.
//!
//! # Signal handling
//!
//! - `SIGINT`  (Ctrl+C): graceful shutdown.
//! - `SIGTERM` (systemd / AWS stop): graceful shutdown.
//! - `SIGKILL`:          not catchable — tokio tasks are abandoned by the OS.
//!
//! # Log levels
//!
//! Controlled by the `RUST_LOG` environment variable:
//! ```text
//! RUST_LOG=sniper_bot=debug,info   # debug for this crate, info for everything else
//! RUST_LOG=info                    # default
//! RUST_LOG=warn                    # production (quiet)
//! ```

use std::time::Instant;

use tracing::{error, info, warn};
use tracing_subscriber::{
    fmt::{self, time::ChronoLocal},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

mod config;
mod errors;
mod executor;
mod market_fetcher;
mod situation_room;
mod sniper;
mod state;
mod streams;

use config::CONFIG;
use sniper::SniperBrain;

// ─────────────────────────────────────────────────────────────────────────────
// Tokio runtime entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Main entry point.
///
/// The `#[tokio::main]` macro expands to a synchronous `main` that:
/// 1. Builds a multi-thread `Runtime` (work-stealing, threads = logical CPUs).
/// 2. Calls `async_main()` on that runtime.
/// 3. Waits for `async_main()` to complete before returning.
///
/// `flavor = "multi_thread"` is explicit here — we never want the
/// single-thread scheduler, which would serialize Binance and Polymarket
/// WS tasks onto one thread and introduce head-of-line blocking latency.
///
/// `worker_threads` is left to the default (= number of logical CPUs).
/// On the c7g.large (2 vCPUs), this is 2. On larger instances, tokio
/// automatically scales to fill available cores.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // ── Step 1: Initialise structured logging ─────────────────────────────────
    // Set up tracing-subscriber with:
    // - `EnvFilter`: reads RUST_LOG. Defaults to "info" if not set.
    // - `ChronoLocal` timer: timestamps match the Python bot's log format.
    // - ANSI colour output to stderr when attached to a terminal.
    //
    // For production (systemd / CloudWatch), set RUST_LOG=info and pipe stderr
    // to a log aggregator. The ChronoLocal format produces human-readable
    // timestamps; switch to `.json()` for structured log aggregation.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_timer(ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f".into()))
                .with_target(true)
                .with_thread_ids(false)
                .with_ansi(atty_stderr()),
        )
        .init();

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  🦀 Sniper Bot — native Rust aarch64 HFT rewrite");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // ── Step 2: Force CONFIG initialisation ───────────────────────────────────
    // Touching CONFIG here triggers the `once_cell::sync::Lazy` initialiser,
    // which calls `Config::load()`. If the environment is misconfigured, the
    // process panics NOW — before any WebSocket connects or capital is at risk.
    //
    // This is intentional: a misconfigured bot must not silently trade.
    let boot_start = Instant::now();
    info!("Loading configuration from environment / .env ...");
    let _ = &*CONFIG; // Force lazy init.

    // ── Step 3: Log the active config summary ─────────────────────────────────
    info!("{}", *CONFIG);
    info!(
        boot_elapsed_ms = boot_start.elapsed().as_millis(),
        "Configuration loaded and validated."
    );

    // ── Step 4: Construct and start the SniperBrain ───────────────────────────
    info!("Initialising SniperBrain...");
    let brain = SniperBrain::new();

    if let Err(e) = brain.start().await {
        error!(
            error = %e,
            "❌ Critical failure during SniperBrain startup. Exiting."
        );
        std::process::exit(1);
    }

    info!("✅ Bot is LIVE. All background tasks running. Listening for momentum events...");
    info!("   Press Ctrl+C or send SIGTERM to initiate graceful shutdown.");

    // ── Step 5: Wait for shutdown signal ─────────────────────────────────────
    // The bot now runs entirely in its spawned background tasks. This task
    // (the "main" task) blocks here until a shutdown signal is received.
    //
    // We listen for both SIGINT (Ctrl+C on interactive terminals) and
    // SIGTERM (sent by systemd, Docker, or AWS ECS to stop the container).
    // Whichever arrives first triggers the graceful shutdown path.
    tokio::select! {
        _ = sigint() => {
            info!("📴 SIGINT received — initiating graceful shutdown...");
        }
        _ = sigterm() => {
            info!("📴 SIGTERM received — initiating graceful shutdown...");
        }
    }

    // ── Step 6: Graceful shutdown ─────────────────────────────────────────────
    // Log a final summary. Background tasks will be cancelled when the
    // tokio runtime is dropped at the end of this function.
    //
    // In a future iteration, we can:
    // 1. Signal each task to stop gracefully via a CancellationToken.
    // 2. Wait for in-flight order submissions to complete (with a timeout).
    // 3. Write a final position / P&L summary to the CSV log.
    //
    // For now, tokio drops all spawned tasks when the runtime exits.
    // In-flight HTTP orders that have already been sent will still be
    // processed by the CLOB — they are not cancelled on our side.
    warn!("Sniper Bot shutting down. Any open positions will NOT be automatically closed.");
    warn!("Review open positions manually via the Polymarket UI or scripts/check_portfolio.py.");

    info!(
        total_uptime_sec = boot_start.elapsed().as_secs(),
        "👋 Shutdown complete. Goodbye."
    );

    // Flush any remaining tracing events before the process exits.
    // tracing-subscriber's fmt layer flushes on drop, but an explicit
    // sleep gives the async runtime a moment to drain the log queue.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Await a SIGINT signal (Ctrl+C).
///
/// Falls back to a future that never resolves on platforms that don't support
/// `tokio::signal::ctrl_c` (extremely rare — only relevant for WASM targets).
async fn sigint() {
    match tokio::signal::ctrl_c().await {
        Ok(())  => {}
        Err(e)  => {
            warn!(error = %e, "Failed to install SIGINT handler — shutdown via SIGTERM only.");
            // Park forever; the SIGTERM branch will handle shutdown.
            std::future::pending::<()>().await;
        }
    }
}

/// Await a SIGTERM signal (sent by systemd / Docker / AWS ECS).
///
/// On non-Unix platforms (e.g. Windows), SIGTERM is not available.
/// We fall back to a future that never resolves, so the bot can still
/// be stopped via Ctrl+C on those platforms.
#[cfg(unix)]
async fn sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(e) => {
            warn!(error = %e, "Failed to install SIGTERM handler.");
            std::future::pending::<()>().await;
        }
    }
}

/// SIGTERM stub for non-Unix platforms.
#[cfg(not(unix))]
async fn sigterm() {
    std::future::pending::<()>().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Terminal detection
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if stderr is connected to an interactive terminal (TTY).
///
/// Used to enable ANSI colour codes in the tracing subscriber output.
/// When running under systemd or piped to a log aggregator, ANSI is disabled
/// to avoid polluting the log with escape sequences.
fn atty_stderr() -> bool {
    // `std::io::stderr` is always a valid handle; `IsTerminal` is stable since Rust 1.70.
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}
