//! main.rs — Tokio runtime entry point for the sniper bot.
//!
//! # Startup sequence
//!
//! 1.  Load `.env` via `dotenvy` **before** any env-var reads, so that `RUST_LOG`
//!     and all trading parameters are visible to every subsequent init step.
//! 2.  Initialise structured logging (tracing-subscriber, ChronoLocal timestamps).
//! 3.  Force `CONFIG` initialisation — panics early on bad env rather than mid-trade.
//! 4.  Construct `SharedState` (the single Arc-wrapped source of truth).
//! 5.  Resolve the active market from the Polymarket Gamma API.
//! 6.  Initialise `ClobExecutor` (HTTP order engine + paper/live bankroll).
//! 7.  Spawn SituationRoom heuristics loop (500 ms background task).
//! 8.  Spawn Polymarket L2 order-book WebSocket task.
//! 9.  Spawn Binance aggTrade WebSocket task (the hot-path tick driver).
//! 10. Spawn the global position manager (take-profit / stop-loss / auto-redeem).
//! 11. Block the main task on `SIGINT` / `SIGTERM` — background tasks run freely.
//! 12. Graceful shutdown: log summary, flush tracing, exit.
//!
//! # Runtime configuration
//!
//! Uses the Tokio multi-thread scheduler (work-stealing, N threads = logical CPUs).
//! On a 2-vCPU instance this gives one thread naturally "owned" by Binance and one
//! by Polymarket + SituationRoom, eliminating head-of-line blocking between streams.
//!
//! # Signal handling
//!
//! - `SIGINT`  (Ctrl+C): graceful shutdown.
//! - `SIGTERM` (systemd / Docker / ECS): graceful shutdown.
//! - `SIGKILL`:          not catchable — tasks are abandoned by the OS.
//!
//! # Log levels
//!
//! Controlled by the `RUST_LOG` environment variable (settable in `.env`):
//! ```text
//! RUST_LOG=sniper_bot=debug,info   # verbose for this crate, info for deps
//! RUST_LOG=info                    # sensible default
//! RUST_LOG=warn                    # quiet production mode
//! ```
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use std::sync::Arc;
use std::time::Instant;

use tracing::{error, info, warn};
use tracing_subscriber::{
    fmt::{self, time::ChronoLocal},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

// ── Module declarations ───────────────────────────────────────────────────────
// Each module is a separate source file under src/.  They are compiled as part
// of the `sniper_bot` crate and their public items are re-exported below.
mod config;
mod errors;
mod executor;
mod market_fetcher;
mod situation_room;
mod sniper;     // kept for tests; SniperBrain is not used directly in main
mod state;
mod streams;

// ── Selective imports ─────────────────────────────────────────────────────────
use config::CONFIG;
use executor::ClobExecutor;
use market_fetcher::MarketFetcher;
use situation_room::SituationRoom;
use state::SharedState;
use streams::{run_binance_stream, run_polymarket_stream};

// ─────────────────────────────────────────────────────────────────────────────
// Tokio runtime entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Main entry point.
///
/// `flavor = "multi_thread"` is explicit — the single-thread scheduler would
/// serialise Binance and Polymarket WS tasks and introduce latency spikes.
/// `worker_threads` defaults to the number of logical CPUs.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // ── Step 1: Load .env ─────────────────────────────────────────────────────
    // Must happen BEFORE tracing init so that RUST_LOG (if set in .env) is
    // visible to EnvFilter, and BEFORE the CONFIG Lazy fires so every env-var
    // read inside Config::load() sees the file's values.
    //
    // `dotenvy::dotenv()` does NOT override variables that are already set in
    // the OS environment, making it safe to call again inside the CONFIG Lazy.
    // We use `eprintln!` here because tracing is not yet initialised.
    match dotenvy::dotenv() {
        Ok(path) => eprintln!("[startup] .env loaded from: {}", path.display()),
        Err(e)   => eprintln!("[startup] No .env file found (using OS environment): {e}"),
    }

    // ── Step 2: Initialise structured logging ─────────────────────────────────
    // EnvFilter reads RUST_LOG (now available from .env if it was set there).
    // ChronoLocal timestamps match the Python bot's log format for easy
    // side-by-side comparisons.  ANSI colours are enabled only on real TTYs so
    // piped / systemd logs stay clean.
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

    // ── Step 3: Initialize Config ─────────────────────────────────────────────
    // Touching CONFIG triggers the `once_cell::Lazy` initialiser, which calls
    // Config::load().  All fields are validated at this point.  If the env is
    // misconfigured, the process panics NOW — before any capital is at risk.
    let boot_start = Instant::now();
    info!("Loading configuration from environment / .env ...");
    let _ = &*CONFIG; // Force lazy init — panics on any validation error.
    info!("{}", *CONFIG);
    info!(
        boot_elapsed_ms = boot_start.elapsed().as_millis(),
        "Configuration loaded and validated."
    );

    // ── Step 4: Create SharedState ────────────────────────────────────────────
    // `SharedState::new()` returns `Arc<SharedState>` — the single source of
    // truth for all lock-free atomic fields shared across every task.
    //
    // All subsequent components receive a clone of this Arc; no component
    // owns the state exclusively, and none of them can outlive the Arc.
    info!("Initialising shared state...");
    let state: Arc<SharedState> = SharedState::new();

    // ── Step 5: Resolve initial market ───────────────────────────────────────
    // The MarketFetcher makes an HTTP call to the Polymarket Gamma API to
    // determine which binary-options token pair is active for the current
    // time window.  On success, the market info is atomically published into
    // SharedState and the sniper is armed.
    //
    // Failure here is NON-FATAL: the bot starts disarmed and the rollover
    // handler will retry when the next window opens.
    let market_fetcher = MarketFetcher::new();
    match market_fetcher.update_market(false).await {
        Ok(info) => {
            info!(
                market_slug = %info.market_slug,
                token_up    = %info.token_id_up,
                token_down  = %info.token_id_down,
                expiry_ts   = info.expiry_ts,
                "✅ Initial market resolved."
            );
            // Atomic pointer-swap — O(1), no lock.
            state.publish_market(info);
            // Arm the sniper so tick evaluation begins immediately.
            state.sniper.arm();
            info!("🎯 Sniper ARMED on initial market.");
        }
        Err(e) => {
            error!(
                error = %e,
                "❌ Failed to fetch initial market. Bot starting DISARMED — \
                 will retry on the next rollover."
            );
        }
    }

    // ── Step 6: Initialize ClobExecutor ──────────────────────────────────────
    // Builds the shared reqwest HTTP client, derives L2 credentials from the
    // private key (if configured), and sets the initial bankroll:
    //   - Paper mode: from CONFIG.starting_bankroll.
    //   - Live mode:  0.0 here; reconciled from on-chain USDC balance on the
    //                 first iteration of the position manager.
    info!("Initialising CLOB executor...");
    let executor = ClobExecutor::new(Arc::clone(&state));

    // ── Step 7: Spawn SituationRoom heuristics loop ───────────────────────────
    // Runs every 500 ms on a dedicated tokio task.  Reads the current EMA,
    // order-book snapshot, and market timing to compute dynamic momentum
    // thresholds and EV scores, then publishes them atomically into SharedState
    // via an ArcSwap so the Binance hot path sees them without a lock.
    SituationRoom::new().start(Arc::clone(&state));
    info!("SituationRoom heuristics loop spawned.");

    // ── Step 8: Spawn Polymarket WebSocket task ───────────────────────────────
    // Connects to the Polymarket L2 CLOB WebSocket and maintains a live
    // order-book snapshot for the active binary-options token pair.
    // The task auto-reconnects on disconnect and waits for the rollover
    // signal before resubscribing with updated token IDs.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_polymarket_stream(state).await;
        });
        info!(url = %CONFIG.poly_ws_url, "Polymarket WS task spawned.");
    }

    // ── Step 9: Spawn Binance WebSocket task ─────────────────────────────────
    // Connects to the Binance aggTrade stream for the configured asset.
    // This is the hot-path tick driver — every message updates the EMA and
    // price-delta atomics, then calls `state.evaluate_delta()` to check
    // whether a momentum threshold has been crossed.
    // The market_fetcher Arc is forwarded so the rollover handler inside this
    // task can re-resolve the Gamma API without a separate HTTP client.
    {
        let state = Arc::clone(&state);
        let mf    = Arc::clone(&market_fetcher);
        let exec  = Arc::clone(&executor);
        tokio::spawn(async move {
            run_binance_stream(state, mf, exec).await;
        });
        info!(url = %CONFIG.binance_ws_url, "Binance aggTrade WS task spawned.");
    }

    // ── Step 10: Spawn global position manager ────────────────────────────────
    // Polls open positions every 3 seconds.  For each position it evaluates:
    //   - Take-profit trigger (unrealised PnL >= configured threshold).
    //   - Impatience exit (position held too long without reaching TP).
    //   - Safe-expiry exit (near expiry with a favourable bid).
    //   - Auto-redeem (market expired, shares need to be redeemed on-chain).
    // Also reconciles the live bankroll from on-chain USDC every 60 seconds.
    {
        let exec = Arc::clone(&executor);
        tokio::spawn(async move {
            exec.run_position_manager().await;
        });
        info!("Global position manager task spawned.");
    }

    info!("✅ Bot is LIVE. All background tasks running. Listening for momentum events...");
    info!("   Press Ctrl+C or send SIGTERM to initiate graceful shutdown.");

    // ── Step 11: Keep main thread alive ──────────────────────────────────────
    // All trading logic runs in the spawned background tasks above.
    // This task (the "main" task) blocks here until an OS shutdown signal is
    // received.  The Arc refs below keep state/executor alive until we're ready
    // to shut down, even though the tasks hold their own clones.
    //
    // We listen for both SIGINT (Ctrl+C) and SIGTERM (systemd / Docker / ECS).
    // Whichever arrives first unblocks the select! and proceeds to shutdown.
    let _ = (&state, &executor, &market_fetcher); // suppress unused-var warnings

    tokio::select! {
        _ = sigint()  => { info!("📴 SIGINT received — initiating graceful shutdown..."); }
        _ = sigterm() => { info!("📴 SIGTERM received — initiating graceful shutdown..."); }
    }

    // ── Step 12: Graceful shutdown ────────────────────────────────────────────
    // Log a final summary.  Background tasks are cancelled when the tokio
    // runtime is dropped at the end of this function.
    //
    // In-flight HTTP orders that have already been sent will still be processed
    // by the CLOB — they are NOT cancelled on our side by this shutdown.
    //
    // Future work:
    //   - Signal each task via a CancellationToken and await JoinHandles.
    //   - Wait for in-flight order submissions to complete (with a timeout).
    //   - Write a final position / P&L summary to the CSV log.
    warn!("Sniper Bot shutting down. Any open positions will NOT be automatically closed.");
    warn!("Review open positions manually via the Polymarket UI or scripts/check_portfolio.py.");

    info!(
        total_uptime_sec = boot_start.elapsed().as_secs(),
        "👋 Shutdown complete. Goodbye."
    );

    // Give the async runtime a brief window to flush buffered tracing events
    // before the process exits.  The fmt layer flushes on drop, but spawned
    // I/O tasks may still hold the last few log records in flight.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Await a SIGINT signal (Ctrl+C).
///
/// On platforms where `ctrl_c()` is unavailable, parks forever so the SIGTERM
/// branch handles the shutdown instead.
async fn sigint() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(e) => {
            warn!(
                error = %e,
                "Failed to install SIGINT handler — shutdown via SIGTERM only."
            );
            // Park forever; SIGTERM branch will handle shutdown.
            std::future::pending::<()>().await;
        }
    }
}

/// Await a SIGTERM signal (sent by systemd / Docker / AWS ECS).
///
/// On non-Unix platforms (e.g. Windows), SIGTERM is unavailable.  We fall back
/// to a future that never resolves so the bot can still be stopped via Ctrl+C.
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
/// When running under systemd or piped to a log aggregator, ANSI sequences are
/// disabled to avoid polluting structured log output with escape codes.
fn atty_stderr() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}
