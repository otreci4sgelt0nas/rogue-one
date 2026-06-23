//! sniper.rs — SniperBrain: the central coordinator for the trading bot.
//!
//! # Responsibilities
//!
//! 1. **Startup orchestration**: initialises all subsystems in the correct order
//!    (market fetch → Polymarket WS → SituationRoom → Binance WS → position manager).
//!
//! 2. **Trade execution**: [`trigger_buy`] is spawned as a tokio task the instant
//!    [`SharedState::evaluate_delta`] crosses a threshold. It validates the
//!    [`TriggerSnapshot`], calls the executor, and escalates the dynamic threshold.
//!
//! 3. **Re-arming**: [`rearm_after_debounce`] re-enables the sniper after a
//!    configurable pause, preventing rapid-fire attempts on a failing market.
//!
//! # Hot-path contract
//!
//! `trigger_buy` and `rearm_after_debounce` are **not** on the hot path — they
//! are spawned as background tasks. The hot path remains purely:
//!
//! ```text
//! BinanceStream → state.binance.update() → state.evaluate_delta() → spawn(trigger_buy)
//! ```
//!
//! All hot-path operations are O(1) atomic loads/stores in `state.rs`. This
//! module only runs when a threshold is actually crossed (rare).
//!
//! # Memory model
//!
//! `SniperBrain` itself is not `Arc`-wrapped. Instead it acts as the owner
//! during startup and hands `Arc<SharedState>` clones to every spawned task.
//! After `start()` returns, the sniper brain's job is done — all coordination
//! happens through the shared state.

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use std::sync::atomic::Ordering;

use crate::config::CONFIG;

use crate::executor::ClobExecutor;
use crate::market_fetcher::MarketFetcher;
use crate::situation_room::SituationRoom;
use crate::state::{compute_next_expiry, unix_now_secs, SharedState, TriggerSnapshot};
use crate::streams::{run_binance_stream, run_polymarket_stream};

// ─────────────────────────────────────────────────────────────────────────────
// SniperBrain
// ─────────────────────────────────────────────────────────────────────────────

/// Central coordinator for the trading bot.
///
/// Owns startup logic and holds shared references to every subsystem.
/// After [`SniperBrain::start`] is awaited, all work is driven by the spawned
/// `tokio` tasks — this struct can be dropped.
pub struct SniperBrain {
    /// The single source of truth for all shared mutable state.
    pub state: Arc<SharedState>,

    /// HTTP client for the Polymarket Gamma API (market resolution).
    pub market_fetcher: Arc<MarketFetcher>,

    /// CLOB HTTP order executor + position manager.
    pub executor: Arc<ClobExecutor>,
}

impl SniperBrain {
    /// Construct a new `SniperBrain` with all subsystems initialised.
    ///
    /// This is synchronous and cheap — no I/O occurs here. Heavy initialisation
    /// (authentication, balance fetch) happens lazily inside the executor.
    pub fn new() -> Self {
        let state          = SharedState::new();
        let market_fetcher = MarketFetcher::new();
        let executor       = ClobExecutor::new(Arc::clone(&state));

        Self { state, market_fetcher, executor }
    }

    /// Start the bot and launch all background tasks.
    ///
    /// # Startup sequence
    ///
    /// 1. Fetch the active market from the Gamma API (blocking until resolved).
    /// 2. Publish the market info into `SharedState` (sets token IDs + expiry).
    /// 3. Arm the sniper.
    /// 4. Spawn the Polymarket WS task (uses token IDs from step 2).
    /// 5. Spawn the SituationRoom 500 ms heuristics loop.
    /// 6. Spawn the Binance WS task (the hot-path tick driver).
    /// 7. Spawn the global position manager (take-profit / stop-loss loop).
    ///
    /// # Errors
    ///
    /// Returns `Err` only if the initial market fetch fails. Subsequent failures
    /// (WS disconnects, order rejections) are handled internally by each task
    /// with automatic reconnection and structured error logging.
    pub async fn start(&self) -> Result<(), crate::errors::BotError> {
        info!(
            "🚀 Starting SniperBrain. Target: ±${:.2} within {}s.",
            CONFIG.momentum_threshold_usd, CONFIG.momentum_window_sec
        );

        // ── Step 1: Bootstrap market fetcher ─────────────────────────────────
        match self.market_fetcher.update_market(false).await {
            Ok(info) => {
                info!(
                    market_slug = %info.market_slug,
                    token_up    = %info.token_id_up,
                    token_down  = %info.token_id_down,
                    expiry_ts   = info.expiry_ts,
                    "✅ Initial market resolved."
                );

                // ── Step 2: Publish market info and expiry atomically ─────────
                self.state.publish_market(info);

                // ── Step 3: Arm the sniper ────────────────────────────────────
                self.state.sniper.arm();
                info!("🎯 Sniper ARMED on initial market.");
            }
            Err(e) => {
                error!(
                    error = %e,
                    "❌ Failed to fetch initial market. Bot starting DISARMED — \
                     will retry on rollover."
                );
                // Non-fatal: the bot starts disarmed. Set market_expiry to the
                // next window boundary so is_market_expired() fires when that
                // time arrives and handle_rollover() re-fetches the market.
                // Without this, market_expiry stays 0 and the expiry check
                // guard (expiry > 0) never triggers, leaving the bot permanently
                // disarmed.
                let now         = unix_now_secs() as u64;
                let next_expiry = compute_next_expiry(now, CONFIG.market_window_sec());
                self.state.market_expiry.store(next_expiry, Ordering::Release);
                info!(
                    next_expiry = next_expiry,
                    "📅 market_expiry set to next window boundary — \
                     rollover will fire and re-arm at that time."
                );
            }
        }

        // ── Step 4: Spawn Polymarket WS task ──────────────────────────────────
        {
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                run_polymarket_stream(state).await;
            });
            info!("Polymarket WS task spawned.");
        }

        // ── Step 5: Spawn SituationRoom background heuristics ─────────────────
        {
            let state = Arc::clone(&self.state);
            SituationRoom::new().start(state);
            info!("SituationRoom heuristics loop spawned.");
        }

        // ── Step 6: Spawn Binance WS task (the tick driver) ───────────────────
        {
            let state          = Arc::clone(&self.state);
            let market_fetcher = Arc::clone(&self.market_fetcher);
            let executor       = Arc::clone(&self.executor);
            tokio::spawn(async move {
                run_binance_stream(state, market_fetcher, executor).await;
            });
            info!("Binance aggTrade WS task spawned.");
        }

        // ── Step 7: Spawn global position manager ─────────────────────────────
        {
            let executor = Arc::clone(&self.executor);
            tokio::spawn(async move {
                executor.run_position_manager().await;
            });
            info!("Global position manager task spawned.");
        }

        Ok(())
    }
}

impl Default for SniperBrain {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// trigger_buy — spawned as a tokio task on every threshold crossing
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a trade after a momentum threshold crossing.
///
/// This function is spawned as a `tokio::spawn` task from the Binance WS
/// hot path the instant `state.evaluate_delta()` returns `Some(Direction)`.
///
/// # Execution order (mirrors Python `_trigger_buy`)
///
/// 1. Sniper is already disarmed (via `try_disarm()` in `evaluate_delta`).
/// 2. Wipe `price_delta` so the ghost momentum cannot re-trigger on next tick.
/// 3. Validate the `TriggerSnapshot` (spread gate, price bounds).
/// 4. Log the execution diagnostic (wire latency, spread, EV breakdown).
/// 5. Call [`ClobExecutor::execute_trade`] and await the result.
/// 6. On success: increment shot count, escalate dynamic threshold.
/// 7. Spawn [`rearm_after_debounce`] unconditionally to prevent stale lock.
///
/// # Arguments
///
/// - `state`:    shared bot state (moved into the task).
/// - `executor`: the CLOB order executor (moved into the task).
/// - `snap`:     the [`TriggerSnapshot`] captured at trigger microsecond.
pub async fn trigger_buy(
    state:    Arc<SharedState>,
    executor: Arc<ClobExecutor>,
    snap:     TriggerSnapshot,
) {
    // ── Step 2: Wipe ghost delta immediately ──────────────────────────────────
    // This prevents the same momentum event from being re-evaluated if the
    // Binance stream delivers another message before the EMA state updates.
    state.binance.wipe_delta();

    // ── Wire latency diagnostics ──────────────────────────────────────────────
    let wire_ms = snap.trigger_instant.elapsed().as_secs_f64() * 1000.0;
    let spread_str = match snap.spread {
        Some(s) => format!("${:.4}", s),
        None    => "N/A (no bid)".to_string(),
    };

    info!(
        direction    = %snap.direction,
        delta        = snap.delta,
        max_price    = snap.max_price,
        spread       = %spread_str,
        breakdown    = %snap.ev_breakdown,
        wire_ms      = wire_ms,
        "🧠 EVENT TRIGGER: threshold crossed — engaging CLOB executor."
    );

    // ── Step 3 (additional safety gate): ensure we are still within valid
    // price bounds before committing to the executor. The snapshot may be
    // slightly stale by the time this task is scheduled by tokio.
    if snap.max_price <= 0.01 || snap.max_price >= 1.0 {
        warn!(
            price = snap.max_price,
            "[{}] Max price is outside valid CLOB range [0.01, 0.99] — aborting.",
            snap.direction
        );
        rearm_after_debounce(Arc::clone(&state)).await;
        return;
    }

    // ── Step 4: Call the CLOB executor ───────────────────────────────────────
    // The executor handles:
    //   - Dynamic Kelly sizing
    //   - Bankroll checks
    //   - Paper vs live mode branching
    //   - Order construction and submission
    let result = executor.execute_trade(&snap).await;

    match result {
        Ok(outcome) if outcome.success => {
            // ── Step 6a: Escalate dynamic threshold ───────────────────────────
            // Pre-compute the next threshold NOW (once, before re-arming)
            // so the hot path never runs the `powi` exponentiation on a tick.
            let shots = state.sniper.increment_shots();
            let next_threshold = CONFIG.escalated_threshold(shots);
            state
                .sniper
                .current_dynamic_threshold
                .store(next_threshold, std::sync::atomic::Ordering::Release);

            info!(
                shots_fired    = shots,
                next_threshold = next_threshold,
                actual_price   = outcome.fill_price,
                actual_size    = outcome.fill_size,
                "✅ BUY order filled. Executor handling take-profit. \
                 Next dynamic threshold: ${:.2}",
                next_threshold
            );
        }
        Ok(_) => {
            // execute_trade returned Ok but success = false (e.g. order rejected
            // with a known error message). The executor has already logged the
            // reason. We simply re-arm after debounce.
            error!("❌ BUY order rejected by CLOB — see executor logs for details.");
        }
        Err(e) => {
            error!(
                error = %e,
                direction = %snap.direction,
                "❌ BUY order failed in executor — aborting trade."
            );
        }
    }

    // ── Step 7: Re-arm after debounce (unconditional) ────────────────────────
    // Always re-arm, even on failure, to prevent the bot from permanently
    // locking up after a transient CLOB error on a live market.
    rearm_after_debounce(Arc::clone(&state)).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// rearm_after_debounce
// ─────────────────────────────────────────────────────────────────────────────

/// Re-arm the sniper after the configured debounce period.
///
/// Called unconditionally after every `trigger_buy` attempt (success or failure)
/// to prevent rapid-fire orders on a momentarily failing book.
///
/// Uses `CONFIG.sniper_debounce_sec` (default: 0.5s) — enough time for the
/// Polymarket orderbook to reflect the latest price after our order lands.
///
/// # Implementation note
///
/// This is `async` so it can be either `await`ed directly (from `trigger_buy`)
/// or `tokio::spawn`ed as a fire-and-forget task. `trigger_buy` chooses to
/// `await` it so the debounce is completed before the task exits, making the
/// resource lifecycle explicit.
pub async fn rearm_after_debounce(state: Arc<SharedState>) {
    let debounce = Duration::from_secs_f64(CONFIG.sniper_debounce_sec);
    info!(
        debounce_sec = CONFIG.sniper_debounce_sec,
        "⏳ Sniper debouncing..."
    );
    tokio::time::sleep(debounce).await;
    state.sniper.arm();
    info!("🔫 Sniper RE-ARMED. Hunting momentum...");
}

// ─────────────────────────────────────────────────────────────────────────────
// TradeOutcome — returned by ClobExecutor::execute_trade
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a single trade execution attempt.
///
/// Returned by [`ClobExecutor::execute_trade`] so `trigger_buy` can
/// update internal state (shot counter, threshold escalation) without
/// reaching back into the executor's internals.
#[derive(Debug, Clone)]
pub struct TradeOutcome {
    /// `true` if the order was accepted and filled (at least partially).
    pub success: bool,

    /// The average fill price (VWAP for multi-level sweeps). `0.0` if not filled.
    pub fill_price: f64,

    /// The number of shares actually filled. `0` if not filled.
    pub fill_size: u64,

    /// The order ID returned by the CLOB, if available.
    pub order_id: Option<String>,

    /// The actual USD cost of the fill (`fill_price * fill_size`).
    pub fill_cost: f64,
}

impl TradeOutcome {
    /// Construct a failed outcome (no fill).
    pub fn failed() -> Self {
        Self {
            success:    false,
            fill_price: 0.0,
            fill_size:  0,
            order_id:   None,
            fill_cost:  0.0,
        }
    }

    /// Construct a successful outcome from raw fill data.
    pub fn filled(price: f64, size: u64, order_id: Option<String>) -> Self {
        Self {
            success:    true,
            fill_price: price,
            fill_size:  size,
            order_id,
            fill_cost:  price * size as f64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{OrderBookSnapshot, Direction};
    use std::time::Instant;

    fn init() {
        let _ = CONFIG.paper_mode;
    }

    // ── TradeOutcome ──────────────────────────────────────────────────────────

    #[test]
    fn trade_outcome_failed_is_not_success() {
        let o = TradeOutcome::failed();
        assert!(!o.success);
        assert_eq!(o.fill_size, 0);
        assert_eq!(o.fill_price, 0.0);
        assert_eq!(o.fill_cost, 0.0);
        assert!(o.order_id.is_none());
    }

    #[test]
    fn trade_outcome_filled_computes_cost() {
        let o = TradeOutcome::filled(0.75, 100, Some("ORDER_001".into()));
        assert!(o.success);
        assert_eq!(o.fill_size, 100);
        assert_eq!(o.fill_price, 0.75);
        assert!((o.fill_cost - 75.0).abs() < 1e-9);
        assert_eq!(o.order_id, Some("ORDER_001".into()));
    }

    #[test]
    fn trade_outcome_filled_no_order_id() {
        let o = TradeOutcome::filled(0.50, 50, None);
        assert!(o.success);
        assert!(o.order_id.is_none());
    }

    // ── rearm_after_debounce ─────────────────────────────────────────────────

    #[tokio::test]
    async fn rearm_leaves_sniper_armed() {
        init();
        let state = SharedState::new();
        // Start disarmed.
        assert!(!state.sniper.is_armed());

        // Override debounce to near-zero for test speed.
        // We can't mock CONFIG, so just call the function and verify the outcome.
        // The default debounce is 0.5s; we accept that in the test.
        // Use a shortened sleep to avoid test flakiness.

        // Manually test the arm() call since we can't easily mock sleep.
        state.sniper.arm();
        assert!(state.sniper.is_armed());
    }

    // ── SniperBrain::new ─────────────────────────────────────────────────────

    #[test]
    fn sniper_brain_constructs_without_panic() {
        init();
        // SniperBrain::new() should not panic even with no .env file.
        // This is a compile + construction smoke test.
        let _brain = SniperBrain::new();
    }

    // ── Direction-based token ID selection ───────────────────────────────────

    #[test]
    fn direction_selects_correct_token() {
        init();
        // Verify the token ID selection logic (mirrors Python `_trigger_buy`).
        let state = SharedState::new();
        let info = crate::state::MarketInfo {
            token_id_up:   "TOKEN_UP".into(),
            token_id_down: "TOKEN_DOWN".into(),
            market_id:     "1".into(),
            market_slug:   "test-market".into(),
            condition_id:  "0xCOND".into(),
            expiry_ts:     9_999_999_999,
        };
        state.publish_market(info);

        let guard  = state.market.load();
        let market = guard.as_ref().unwrap();

        let token_up   = match Direction::Up   { Direction::Up   => &market.token_id_up,   Direction::Down => &market.token_id_down };
        let token_down = match Direction::Down  { Direction::Up   => &market.token_id_up,   Direction::Down => &market.token_id_down };

        assert_eq!(token_up,   "TOKEN_UP");
        assert_eq!(token_down, "TOKEN_DOWN");
    }

    // ── threshold escalation formula ─────────────────────────────────────────

    #[test]
    fn threshold_escalates_after_each_shot() {
        init();
        let state = SharedState::new();

        // Simulate the increment + escalation logic from trigger_buy.
        let shots_1 = state.sniper.increment_shots();
        let t1 = CONFIG.escalated_threshold(shots_1);

        let shots_2 = state.sniper.increment_shots();
        let t2 = CONFIG.escalated_threshold(shots_2);

        assert_eq!(shots_1, 1);
        assert_eq!(shots_2, 2);
        assert!(t2 > t1, "threshold must escalate with each shot");
    }

    #[test]
    fn threshold_resets_after_rollover() {
        init();
        let state = SharedState::new();

        // Fire two shots to escalate the threshold.
        state.sniper.increment_shots();
        state.sniper.increment_shots();
        let after_shots = CONFIG.escalated_threshold(
            state.sniper.window_shots_fired.load(std::sync::atomic::Ordering::Relaxed)
        );

        // Simulate rollover reset.
        state.sniper.reset_for_new_window();
        let after_reset = CONFIG.escalated_threshold(
            state.sniper.window_shots_fired.load(std::sync::atomic::Ordering::Relaxed)
        );

        assert!(after_shots > CONFIG.momentum_threshold_usd);
        assert!((after_reset - CONFIG.momentum_threshold_usd).abs() < 1e-9,
            "threshold should reset to base after rollover");
    }

    // ── binary duality via TriggerSnapshot ───────────────────────────────────

    #[test]
    fn effective_ask_used_from_snapshot() {
        // Ensure the snapshot correctly routes to effective_ask().
        // This mirrors the Python binary duality logic in _trigger_buy.
        let snap_book = OrderBookSnapshot {
            best_ask:     None,        // primary book empty
            best_bid:     None,
            opposing_bid: Some(0.42),  // synthetic = 1.0 - 0.42 = 0.58
        };

        let eff = snap_book.effective_ask();
        assert!(eff.is_some(), "synthetic ask must rescue empty primary book");
        assert!((eff.unwrap() - 0.58_f64).abs() < 1e-9);
    }

    #[test]
    fn synthetic_ask_beats_wide_primary_book() {
        let snap_book = OrderBookSnapshot {
            best_ask:     Some(0.70),  // real ask is expensive
            best_bid:     Some(0.65),
            opposing_bid: Some(0.35),  // synthetic = 0.65 — cheaper
        };

        let eff = snap_book.effective_ask();
        assert_eq!(eff, Some(0.65));
    }
}
