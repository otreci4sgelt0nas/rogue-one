//! state.rs — The complete lock-free shared market state for the sniper bot.
//!
//! # Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────────────┐
//!  │                         Arc<SharedState>                            │
//!  │                                                                      │
//!  │  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────┐ │
//!  │  │  BinanceAtomic  │  │  OrderBookAtomic │  │   SniperAtomic     │ │
//!  │  │  ─────────────  │  │  ──────────────  │  │   ─────────────    │ │
//!  │  │  ema_price      │  │  best_ask_up     │  │   is_armed         │ │
//!  │  │  last_ts        │  │  best_ask_down   │  │   trigger_up       │ │
//!  │  │  price_delta    │  │  best_bid_up     │  │   trigger_down     │ │
//!  │  │  current_price  │  │  best_bid_down   │  │   dyn_threshold    │ │
//!  │  └─────────────────┘  └──────────────────┘  │   shots_fired      │ │
//!  │                                              └────────────────────┘ │
//!  │  ┌─────────────────────────────────────────────────────────────────┐│
//!  │  │  ArcSwapOption<MarketInfo>  (atomically published on rollover)  ││
//!  │  │  token_id_up | token_id_down | market_id | slug | condition_id ││
//!  │  └─────────────────────────────────────────────────────────────────┘│
//!  │                                                                      │
//!  │  market_expiry: AtomicU64  │  is_rolling_over: AtomicBool          │
//!  │  poly_reconnect: Notify    │  poly_disconnect: Notify               │
//!  └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Concurrency model
//!
//! | Field group            | Writer task(s)      | Reader task(s)              | Primitive         |
//! |------------------------|---------------------|-----------------------------|-------------------|
//! | BinanceAtomicState     | Binance WS          | Binance WS (same), Rollover | AtomicF64         |
//! | OrderBookAtomicState   | Polymarket WS       | Binance WS (evaluate_trade) | AtomicF64         |
//! | SniperAtomicState      | SituationRoom(500ms)| Binance WS (evaluate_trade) | AtomicF64/Bool/U32|
//! | MarketInfo             | Rollover task       | All (hot path)              | ArcSwapOption     |
//! | market_expiry          | Rollover task       | Binance WS (hot path)       | AtomicU64         |
//! | is_rolling_over        | Binance WS + Rollover| Binance WS, SituationRoom  | AtomicBool        |
//!
//! # Optional price sentinel
//!
//! Polymarket best_ask/bid values are `Option<f64>` in Python. We represent
//! "no price" as `f64::NAN` stored in the atomic, avoiding heap allocation of
//! `Option<f64>` in the hot path. Use [`load_price`] / [`store_price`] helpers.
//!
//! # Memory ordering rationale
//!
//! - **Hot-path reads** (Binance tick handler reading orderbook + triggers):
//!   `Acquire` so they observe all preceding `Release` writes from other tasks.
//! - **Hot-path writes** (Binance tick handler updating its own EMA state):
//!   `Release` on the final write (`price_delta`) so a rollover task that later
//!   reads with `Acquire` sees a consistent state.
//! - **Rollover writes** (EMA reset, expiry update):
//!   `Release` on the last store (`market_expiry`) to ensure all prior resets
//!   are visible to the Binance task when it next loads `market_expiry`.
//! - **Control flags** (`is_rolling_over`, `is_armed`):
//!   `AcqRel` on CAS / compare_exchange; `Release` on plain store, `Acquire` on load.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use portable_atomic::AtomicF64;
use tokio::sync::Notify;
use tracing::{error, info};

use crate::config::CONFIG;


// ─────────────────────────────────────────────────────────────────────────────
// Optional-price sentinel
// ─────────────────────────────────────────────────────────────────────────────

/// The sentinel `f64` value stored in an `AtomicF64` to represent `None`.
///
/// We use `f64::NAN` because all valid Polymarket prices are in the open
/// interval `(0.0, 1.0)`, so NaN is unambiguous and costs no extra branch.
pub const NO_PRICE: f64 = f64::NAN;

/// Load an optional price from an `AtomicF64`.
///
/// Returns `None` if the stored value is NaN (no quote available yet) or
/// non-positive (invalid). Returns `Some(price)` otherwise.
///
/// # Hot-path usage
/// Call with `Ordering::Acquire` when the reader is on a different task than
/// the writer. Call with `Ordering::Relaxed` when the same task both reads and
/// writes (e.g. within the Binance stream task itself).
#[inline(always)]
pub fn load_price(atomic: &AtomicF64, order: Ordering) -> Option<f64> {
    let v = atomic.load(order);
    if v.is_nan() || v <= 0.0 {
        None
    } else {
        Some(v)
    }
}

/// Store an optional price into an `AtomicF64`.
///
/// `None` is stored as [`NO_PRICE`] (NaN). A `Some(price)` that is
/// non-positive or NaN is coerced to `NO_PRICE` defensively.
#[inline(always)]
pub fn store_price(atomic: &AtomicF64, value: Option<f64>, order: Ordering) {
    let raw = match value {
        Some(p) if p > 0.0 && p.is_finite() => p,
        _ => NO_PRICE,
    };
    atomic.store(raw, order);
}

// ─────────────────────────────────────────────────────────────────────────────
// MarketInfo  — immutable snapshot swapped atomically during rollover
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-resolved Polymarket market for a single window.
///
/// This struct is **immutable once constructed**. During rollover, a brand-new
/// `MarketInfo` is built and published via [`SharedState::market`] with a
/// single pointer swap (`ArcSwapOption::store`), making the new market visible
/// to all readers in O(1) with no lock.
///
/// The hot path reads this with:
/// ```rust,ignore
/// let guard = state.market.load();   // single atomic pointer load
/// if let Some(info) = guard.as_ref() {
///     // use info.token_id_up / info.token_id_down
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MarketInfo {
    /// CLOB token ID for the "Up" (or "Yes") leg of the binary market.
    pub token_id_up: String,

    /// CLOB token ID for the "Down" (or "No") leg of the binary market.
    pub token_id_down: String,

    /// Polymarket internal market ID (integer as string).
    pub market_id: String,

    /// Human-readable market slug, e.g. `"btc-updown-15m-1750000000"`.
    pub market_slug: String,

    /// UMA condition ID used for redemption after settlement.
    pub condition_id: String,

    /// Market expiry as a Unix timestamp (seconds).
    ///
    /// Also stored as `SharedState::market_expiry` (AtomicU64) for the
    /// hot-path check without going through the ArcSwap pointer chain.
    pub expiry_ts: u64,

    /// True if this is a neg-risk market (uses the neg-risk exchange contract
    /// `0xC5d563A36AE78145C45a50134d48A1215220f80a` for EIP-712 signing).
    /// BTC/ETH up-down markets are always neg-risk on Polygon mainnet.
    pub neg_risk: bool,
}

impl MarketInfo {
    /// Returns `true` if the given exchange timestamp (seconds, f64) has
    /// reached or passed this market's expiry.
    #[inline(always)]
    pub fn is_expired(&self, exchange_ts_secs: f64) -> bool {
        exchange_ts_secs >= self.expiry_ts as f64
    }

    /// Returns the number of seconds remaining until expiry, floored at 0.
    #[inline(always)]
    pub fn seconds_remaining(&self, now_secs: f64) -> f64 {
        (self.expiry_ts as f64 - now_secs).max(0.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinanceAtomicState  — EMA + tick state, written per-tick
// ─────────────────────────────────────────────────────────────────────────────

/// Lock-free state for the Binance aggTrade EMA calculation.
///
/// Written exclusively by the **Binance WS task** on every incoming tick.
/// Reset (zeroed) by the **rollover task** once per market window.
///
/// All fields are `AtomicF64` (portable-atomic, lock-free on aarch64 via
/// LL/SC native instructions).
///
/// # Invariant
/// `last_ts == 0.0` signals "no tick received yet" — triggers a cold-start
/// where `ema_price` is initialised to the first `current_price`.
#[derive(Debug)]
pub struct BinanceAtomicState {
    /// Time-decayed exponential moving average of `current_price`.
    /// Alpha is computed as `min(1.0, delta_t / window_sec)`.
    pub ema_price: AtomicF64,

    /// Exchange timestamp of the last processed tick (seconds, f64).
    /// `NaN` means no tick has been received since boot or last reset.
    /// Using `NaN` (not `0.0`) allows a genuine tick at `ts = 0.0` to be
    /// distinguished from the "uninitialised" sentinel.
    pub last_ts: AtomicF64,

    /// Current momentum delta: `current_price − ema_price`.
    ///
    /// This is the **primary trigger signal** read by `evaluate_trade`.
    /// It is written with `Release` so the sniper task observes it with `Acquire`.
    pub price_delta: AtomicF64,

    /// Raw price of the last processed aggTrade (before EMA smoothing).
    pub current_price: AtomicF64,
}

impl BinanceAtomicState {
    fn new() -> Self {
        Self {
            ema_price:     AtomicF64::new(0.0),
            last_ts:       AtomicF64::new(f64::NAN), // NaN = "no tick received yet"
            price_delta:   AtomicF64::new(0.0),
            current_price: AtomicF64::new(0.0),
        }
    }

    /// Reset all fields to their boot/cold-start values.
    ///
    /// Called by the rollover task before publishing a new `MarketInfo`.
    /// Uses `Release` ordering on the last store so the Binance task (which
    /// loads `market_expiry` with `Acquire` after rollover) will see all four
    /// zeroes when it processes its first tick on the new market.
    pub fn reset(&self) {
        self.ema_price.store(0.0, Ordering::Relaxed);
        // Restore the NaN sentinel so the next tick triggers a fresh cold-start.
        self.last_ts.store(f64::NAN, Ordering::Relaxed);
        self.current_price.store(0.0, Ordering::Relaxed);
        // Release on the last store — acts as the publication fence.
        self.price_delta.store(0.0, Ordering::Release);
    }

    /// Update the EMA state from a new tick.
    ///
    /// # Arguments
    /// - `price`      : raw aggTrade price from Binance `"p"` field.
    /// - `ts`         : exchange event timestamp in seconds (`msg["E"] / 1000`).
    /// - `window_sec` : EMA decay window (from `CONFIG.momentum_window_sec`).
    ///
    /// # Returns
    /// The newly computed `price_delta` (momentum signal).
    ///
    /// # Ordering
    /// All intermediate stores use `Relaxed` (same task). The final `price_delta`
    /// store uses `Release` so the sniper task's `Acquire` load sees a consistent
    /// view. This is the minimal correct ordering for cross-task communication.
    #[inline]
    pub fn update(&self, price: f64, ts: f64, window_sec: f64) -> f64 {
        let last = self.last_ts.load(Ordering::Relaxed);
        let new_ema = if last.is_nan() {
            // Cold start: seed EMA with the first observed price.
            // NaN sentinel means no tick has been received yet (or after a reset).
            price
        } else {
            let delta_t = (ts - last).max(0.0);
            let alpha = (delta_t / window_sec).min(1.0);
            let old_ema = self.ema_price.load(Ordering::Relaxed);
            price * alpha + old_ema * (1.0 - alpha)
        };

        self.current_price.store(price, Ordering::Relaxed);
        self.ema_price.store(new_ema, Ordering::Relaxed);
        self.last_ts.store(ts, Ordering::Relaxed);

        let delta = price - new_ema;
        // Release: publish the delta so evaluate_trade (on any thread) sees it.
        self.price_delta.store(delta, Ordering::Release);
        delta
    }

    /// Zero out `price_delta` atomically.
    ///
    /// Called immediately when a trade is triggered to prevent the same
    /// momentum signal from being re-evaluated on the next tick.
    #[inline(always)]
    pub fn wipe_delta(&self) {
        self.price_delta.store(0.0, Ordering::Release);
    }

    /// Snapshot all fields for diagnostics (no ordering guarantees — debug only).
    pub fn snapshot(&self) -> BinanceSnapshot {
        BinanceSnapshot {
            ema_price:     self.ema_price.load(Ordering::Relaxed),
            last_ts:       self.last_ts.load(Ordering::Relaxed),
            price_delta:   self.price_delta.load(Ordering::Relaxed),
            current_price: self.current_price.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time copy of [`BinanceAtomicState`] for logging/diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct BinanceSnapshot {
    pub ema_price:     f64,
    pub last_ts:       f64,
    pub price_delta:   f64,
    pub current_price: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// OrderBookAtomicState  — Polymarket L2 best prices, written per-message
// ─────────────────────────────────────────────────────────────────────────────

/// Lock-free L2 orderbook best prices for both legs of the binary market.
///
/// Written by the **Polymarket WS task** on every `book_change` event.
/// Read by the **Binance WS task** inside `evaluate_trade` on every tick.
/// Read by the **SituationRoom task** every 500 ms.
///
/// `f64::NAN` is the sentinel for "no quote available" (`Option<f64>` = `None`).
/// Use [`load_price`] / [`store_price`] to safely read/write.
#[derive(Debug)]
pub struct OrderBookAtomicState {
    /// Best ask (lowest sell offer) for the UP token. `NaN` = no quote.
    pub best_ask_up: AtomicF64,

    /// Best ask (lowest sell offer) for the DOWN token. `NaN` = no quote.
    pub best_ask_down: AtomicF64,

    /// Best bid (highest buy offer) for the UP token. `NaN` = no quote.
    pub best_bid_up: AtomicF64,

    /// Best bid (highest buy offer) for the DOWN token. `NaN` = no quote.
    pub best_bid_down: AtomicF64,
}

impl OrderBookAtomicState {
    fn new() -> Self {
        Self {
            best_ask_up:   AtomicF64::new(NO_PRICE),
            best_ask_down: AtomicF64::new(NO_PRICE),
            best_bid_up:   AtomicF64::new(NO_PRICE),
            best_bid_down: AtomicF64::new(NO_PRICE),
        }
    }

    /// Reset all quotes to "no quote" sentinel.
    ///
    /// Called during rollover to prevent the new market from inheriting stale
    /// prices from the old orderbook.
    pub fn reset(&self) {
        self.best_ask_up.store(NO_PRICE, Ordering::Relaxed);
        self.best_ask_down.store(NO_PRICE, Ordering::Relaxed);
        self.best_bid_up.store(NO_PRICE, Ordering::Relaxed);
        // Release on the last store — publication fence.
        self.best_bid_down.store(NO_PRICE, Ordering::Release);
    }

    /// Take a consistent snapshot of all four prices for use at trigger time.
    ///
    /// Uses `Acquire` ordering on every load so we see the latest `Release`
    /// writes from the Polymarket WS task. This snapshot is captured at the
    /// exact microsecond a trade is triggered and passed to the executor, so
    /// the executor never re-reads from the atomic (avoiding TOCTOU skew).
    #[inline]
    pub fn snapshot_for_direction(&self, direction: Direction) -> OrderBookSnapshot {
        match direction {
            Direction::Up => OrderBookSnapshot {
                best_ask:     load_price(&self.best_ask_up,   Ordering::Acquire),
                best_bid:     load_price(&self.best_bid_up,   Ordering::Acquire),
                opposing_bid: load_price(&self.best_bid_down, Ordering::Acquire),
            },
            Direction::Down => OrderBookSnapshot {
                best_ask:     load_price(&self.best_ask_down, Ordering::Acquire),
                best_bid:     load_price(&self.best_bid_down, Ordering::Acquire),
                opposing_bid: load_price(&self.best_bid_up,   Ordering::Acquire),
            },
        }
    }

    /// Update a single side of the book for a given token.
    ///
    /// Called from the Polymarket WS message handler with the parsed best price.
    /// `Release` ordering ensures the Binance task's `Acquire` read sees the update.
    pub fn update_ask(&self, token_id: &str, price: Option<f64>, market: &MarketInfo) {
        if token_id == market.token_id_up {
            store_price(&self.best_ask_up, price, Ordering::Release);
        } else if token_id == market.token_id_down {
            store_price(&self.best_ask_down, price, Ordering::Release);
        }
    }

    /// Update the best bid for a given token.
    pub fn update_bid(&self, token_id: &str, price: Option<f64>, market: &MarketInfo) {
        if token_id == market.token_id_up {
            store_price(&self.best_bid_up, price, Ordering::Release);
        } else if token_id == market.token_id_down {
            store_price(&self.best_bid_down, price, Ordering::Release);
        }
    }
}

/// A consistent orderbook snapshot captured at trigger microsecond.
///
/// All three prices correspond to the same direction (UP or DOWN).
/// `opposing_bid` is the counterpart token's best bid, used for Binary Duality.
#[derive(Debug, Clone, Copy)]
pub struct OrderBookSnapshot {
    /// Best ask for the target leg (`None` if no quote available).
    pub best_ask: Option<f64>,

    /// Best bid for the target leg (`None` if no quote available).
    pub best_bid: Option<f64>,

    /// Best bid of the **opposing** leg, used to synthesise a ghost ask via
    /// Binary Duality: `synthetic_ask = 1.0 − opposing_bid`.
    pub opposing_bid: Option<f64>,
}

impl OrderBookSnapshot {
    /// Compute the effective ask price, preferring the real ask but falling
    /// back to the synthetic ask derived from Binary Duality.
    ///
    /// In binary markets: `Price(UP) + Price(DOWN) ≈ 1.0`.
    /// Therefore: `synthetic_ask(UP) = 1.0 − best_bid(DOWN)`.
    ///
    /// Returns `None` only if both the real and synthetic asks are unavailable.
    pub fn effective_ask(&self) -> Option<f64> {
        let synthetic = self
            .opposing_bid
            .filter(|&b| b > 0.0)
            .map(|b| 1.0 - b);

        match (self.best_ask, synthetic) {
            (Some(real), Some(syn)) => {
                if syn < real {
                    tracing::debug!(
                        real_ask = real,
                        synthetic_ask = syn,
                        "Binary Duality: synthetic ask beats primary ask"
                    );
                }
                Some(real.min(syn))
            }
            (Some(real), None) => Some(real),
            (None, Some(syn)) => {
                tracing::info!(
                    synthetic_ask = syn,
                    opposing_bid = ?self.opposing_bid,
                    "Binary Duality: primary book empty — using synthetic ask"
                );
                Some(syn)
            }
            (None, None) => None,
        }
    }

    /// Compute the bid-ask spread. Returns `None` if either side is missing.
    #[inline]
    pub fn spread(&self) -> Option<f64> {
        match (self.best_ask, self.best_bid) {
            (Some(ask), Some(bid)) => Some((ask - bid).max(0.0)),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SniperAtomicState  — trigger thresholds and armed status
// ─────────────────────────────────────────────────────────────────────────────

/// Lock-free sniper control flags and pre-merged trigger thresholds.
///
/// The key insight ported from the Python architecture:
/// - `trigger_up` / `trigger_down` are the **fully pre-merged** thresholds
///   written by `SituationRoom` every 500 ms.
/// - `evaluate_trade` does a single `AtomicF64::load(Acquire)` per trigger —
///   no computation, no allocations, no lock contention on the hot path.
#[derive(Debug)]
pub struct SniperAtomicState {
    /// When `false`, all tick evaluations are dropped immediately.
    ///
    /// Set to `false` the instant a trade is triggered.
    /// Set back to `true` after the debounce period completes.
    pub is_armed: AtomicBool,

    /// Minimum positive `price_delta` required to trigger an UP trade.
    ///
    /// Written by `SituationRoom` every 500 ms as:
    ///   `max(current_dynamic_threshold, min_ev_momentum_up)`
    ///
    /// Initialised to `f64::MAX` so no trade fires before SituationRoom computes.
    pub trigger_up: AtomicF64,

    /// Minimum magnitude of negative `price_delta` required to trigger DOWN.
    ///
    /// Same update cadence as `trigger_up`.
    pub trigger_down: AtomicF64,

    /// The base threshold escalated by `(1 + momentum_step_pct)^shots_fired`.
    ///
    /// Pre-computed once per trade in `_trigger_buy` — never recomputed on the
    /// hot tick path. Initialised to `CONFIG.momentum_threshold_usd`.
    pub current_dynamic_threshold: AtomicF64,

    /// Number of trades fired within the current market window.
    ///
    /// Drives the escalating threshold calculation.
    /// Reset to 0 on rollover.
    pub window_shots_fired: AtomicU32,
}

impl SniperAtomicState {
    fn new() -> Self {
        let base = CONFIG.momentum_threshold_usd;
        Self {
            is_armed:                 AtomicBool::new(false),
            trigger_up:               AtomicF64::new(f64::MAX),
            trigger_down:             AtomicF64::new(f64::MAX),
            current_dynamic_threshold: AtomicF64::new(base),
            window_shots_fired:       AtomicU32::new(0),
        }
    }

    /// Disarm the sniper. Returns `true` if it was previously armed (CAS).
    ///
    /// Using `compare_exchange` (AcqRel) prevents a race where two concurrent
    /// tick handlers both see `is_armed == true` and both try to fire.
    #[inline]
    pub fn try_disarm(&self) -> bool {
        self.is_armed
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Re-arm the sniper after the debounce period.
    #[inline(always)]
    pub fn arm(&self) {
        self.is_armed.store(true, Ordering::Release);
    }

    /// Check if the sniper is armed. Cheap `Acquire` load.
    #[inline(always)]
    pub fn is_armed(&self) -> bool {
        self.is_armed.load(Ordering::Acquire)
    }

    /// Update both trigger thresholds atomically.
    ///
    /// Called by `SituationRoom` every 500 ms with the fully merged values:
    ///   `trigger = max(dynamic_threshold, ev_floor)`
    ///
    /// Uses `Release` so the Binance task's `Acquire` loads see the new values.
    #[inline]
    pub fn set_triggers(&self, trigger_up: f64, trigger_down: f64) {
        self.trigger_up.store(trigger_up, Ordering::Release);
        self.trigger_down.store(trigger_down, Ordering::Release);
    }

    /// Increment shot count and return the new value. Relaxed — single writer.
    #[inline]
    pub fn increment_shots(&self) -> u32 {
        // `fetch_add` with Relaxed is safe here: only one task (the executor
        // callback) ever increments this counter per trade, and the result is
        // only used to pre-compute the next threshold (non-critical ordering).
        self.window_shots_fired.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Reset shot count and re-seed the dynamic threshold for a new window.
    ///
    /// Uses `Release` on the last store — rollover publication fence.
    pub fn reset_for_new_window(&self) {
        let base = CONFIG.momentum_threshold_usd;
        self.window_shots_fired.store(0, Ordering::Relaxed);
        self.current_dynamic_threshold.store(base, Ordering::Relaxed);
        self.trigger_up.store(f64::MAX, Ordering::Relaxed);
        // Release on the last store.
        self.trigger_down.store(f64::MAX, Ordering::Release);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Direction — trade direction enum
// ─────────────────────────────────────────────────────────────────────────────

/// The direction of a binary options trade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Up,
    Down,
}

impl Direction {
    /// Returns the opposing direction.
    #[inline(always)]
    pub fn opposite(self) -> Self {
        match self {
            Direction::Up => Direction::Down,
            Direction::Down => Direction::Up,
        }
    }

    /// Returns the human-readable string used in log messages.
    #[inline(always)]
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Up => "UP",
            Direction::Down => "DOWN",
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TriggerSnapshot — point-in-time capture at trigger microsecond
// ─────────────────────────────────────────────────────────────────────────────

/// A complete snapshot of all trade-relevant state captured at the exact
/// microsecond a momentum threshold is crossed.
///
/// This struct is created inside `evaluate_trade` (Binance hot path) and
/// moved into the spawned `_trigger_buy` task. The executor receives this
/// and never re-reads from shared atomics — eliminating TOCTOU skew between
/// threshold crossing and order submission.
#[derive(Debug, Clone)]
pub struct TriggerSnapshot {
    /// Trade direction derived from sign of `delta`.
    pub direction: Direction,

    /// The momentum delta (price − EMA) that crossed the threshold.
    pub delta: f64,

    /// Monotonic instant of threshold crossing (for wire latency measurement).
    pub trigger_instant: Instant,

    /// Unix timestamp (seconds) from the exchange event that crossed the threshold.
    /// Used for logging exchange-clock wire latency without an OS syscall.
    pub exchange_ts: f64,

    /// Orderbook prices captured at trigger microsecond.
    pub book: OrderBookSnapshot,

    /// CLOB token ID for the direction being traded.
    pub token_id: String,

    /// Market slug (for logging).
    pub market_slug: String,

    /// Pre-calculated effective ask at trigger time (may be synthetic via
    /// Binary Duality). `None` aborts the trade before spawning the task.
    pub effective_ask: f64,

    /// Maximum limit price including slippage: `min(effective_ask * slippage_mult, 0.99)`.
    pub max_price: f64,

    /// Bid-ask spread at trigger time (for logging and spread gate).
    pub spread: Option<f64>,

    /// The pre-computed EV breakdown string from the last SituationRoom update.
    /// Cloned once here to avoid holding a reference across an await point.
    pub ev_breakdown: String,

    /// Whether this market is a neg-risk market (uses the neg-risk exchange contract).
    /// BTC/ETH up-down and most binary markets on Polygon are neg-risk.
    pub neg_risk: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// SituationRoomState — threshold breakdown strings (non-atomic, RwLock-guarded)
// ─────────────────────────────────────────────────────────────────────────────

/// The diagnostic breakdown strings produced by `SituationRoom._calculate_required_momentum`.
///
/// These are written every 500 ms and read only when a trade fires (rare).
/// We use `parking_lot::RwLock` — faster than `std::sync::RwLock` on aarch64,
/// never poisons on panic, and the 500ms write cadence means essentially zero
/// contention.
#[derive(Debug, Default, Clone)]
pub struct SituationRoomDiagnostics {
    pub last_breakdown_up:   String,
    pub last_breakdown_down: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// SharedState — the single Arc<SharedState> passed to every task
// ─────────────────────────────────────────────────────────────────────────────

/// The root shared state of the entire sniper bot.
///
/// Constructed once in `main`, wrapped in an [`Arc`], and cloned (cheap pointer
/// increment) for every background task. No `&mut` references ever escape.
///
/// # Rollover sequence
///
/// ```text
/// 1. Binance tick: ts >= expiry
///    → is_rolling_over.CAS(false, true)  [AcqRel]
///    → tokio::spawn(handle_rollover(Arc<SharedState>))
///    → return (drop message)
///
/// 2. handle_rollover:
///    a. sniper.is_armed ← false            [Release]
///    b. poly_disconnect.notify_one()       (Polymarket WS exits its loop)
///    c. book.reset()                       (wipe stale L2 prices)
///    d. binance.reset()                    (zero EMA state)
///    e. sniper.reset_for_new_window()      (reset shots, thresholds)
///    f. market_fetcher.update_market()     (HTTP call, new slug)
///    g. market.store(Arc::new(new_info))   (ArcSwapOption, O(1) publish)
///    h. market_expiry.store(new_ts)        [Release]
///    i. poly_reconnect.notify_one()        (Polymarket WS reconnects)
///    j. sniper.arm()                       [Release]
///    k. is_rolling_over ← false            [Release]
/// ```
#[derive(Debug)]
pub struct SharedState {
    // ── Market metadata (hot read: single pointer deref via ArcSwap) ──────────
    /// Current market info. `None` until the first `MarketFetcher::update_market`
    /// call completes. Atomically replaced during rollover.
    pub market: ArcSwapOption<MarketInfo>,

    /// Market expiry as Unix timestamp seconds (AtomicU64 for O(1) hot-path check
    /// without going through the ArcSwap pointer chain).
    ///
    /// Updated atomically with `Release` as the final step of rollover so that
    /// the Binance task's `Acquire` load sees all preceding state resets.
    pub market_expiry: AtomicU64,

    // ── Rollover control ──────────────────────────────────────────────────────
    /// Set to `true` by the Binance task the instant expiry is detected.
    /// Cleared to `false` by the rollover task as its final step.
    ///
    /// Acts as both a guard against duplicate rollovers and a signal to all
    /// tasks to pause trading until the new market is live.
    pub is_rolling_over: AtomicBool,

    // ── WebSocket stream control ───────────────────────────────────────────────
    /// Fired during rollover step (b): tells the Polymarket WS task to exit
    /// its message loop and prepare for reconnection.
    pub poly_disconnect: Notify,

    /// Fired during rollover step (i): tells the Polymarket WS task to read
    /// the new token IDs from `market` and reconnect.
    pub poly_reconnect: Notify,

    // ── Per-subsystem atomic state ────────────────────────────────────────────
    /// Binance EMA/tick state (written per-tick by Binance WS task).
    pub binance: BinanceAtomicState,

    /// Polymarket L2 orderbook (written per-message by Polymarket WS task).
    pub book: OrderBookAtomicState,

    /// Sniper control flags and pre-computed trigger thresholds.
    pub sniper: SniperAtomicState,

    // ── SituationRoom diagnostics (written every 500ms, read on trade fires) ──
    /// EV breakdown strings — protected by a fast `parking_lot::RwLock` because
    /// they are `String` values (heap-allocated, not suitable for atomic ops).
    pub situation_diag: parking_lot::RwLock<SituationRoomDiagnostics>,
}

impl SharedState {
    /// Construct the initial shared state.
    ///
    /// No market is loaded yet (`market` is `None`).
    /// The sniper starts disarmed; `is_armed` is set to `true` only after
    /// the first `MarketFetcher::update_market` call succeeds.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            market:           ArcSwapOption::empty(),
            market_expiry:    AtomicU64::new(0),
            is_rolling_over:  AtomicBool::new(false),
            poly_disconnect:  Notify::new(),
            poly_reconnect:   Notify::new(),
            binance:          BinanceAtomicState::new(),
            book:             OrderBookAtomicState::new(),
            sniper:           SniperAtomicState::new(),
            situation_diag:   parking_lot::RwLock::new(SituationRoomDiagnostics::default()),
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Convenience accessors for the hot path
    // ─────────────────────────────────────────────────────────────────────────

    /// Returns `true` if the given exchange timestamp (seconds) has reached or
    /// passed the current market's expiry.
    ///
    /// This is the **first check on every Binance tick** — must be O(1).
    /// Uses a single `AtomicU64::load(Acquire)` — no pointer chasing, no lock.
    #[inline(always)]
    pub fn is_market_expired(&self, exchange_ts_secs: f64) -> bool {
        let expiry = self.market_expiry.load(Ordering::Acquire);
        expiry > 0 && exchange_ts_secs >= expiry as f64
    }

    /// Returns `true` if a rollover is currently in progress.
    #[inline(always)]
    pub fn is_rolling_over(&self) -> bool {
        self.is_rolling_over.load(Ordering::Acquire)
    }

    /// Returns the seconds remaining until expiry given an exchange timestamp.
    ///
    /// Returns `0.0` if no market is loaded or expiry has passed.
    #[inline]
    pub fn seconds_to_expiry(&self, exchange_ts_secs: f64) -> f64 {
        let expiry = self.market_expiry.load(Ordering::Relaxed) as f64;
        if expiry == 0.0 {
            return 0.0;
        }
        (expiry - exchange_ts_secs).max(0.0)
    }

    /// Load the current market expiry as a `f64` of Unix seconds.
    #[inline(always)]
    pub fn market_expiry_secs(&self) -> f64 {
        self.market_expiry.load(Ordering::Acquire) as f64
    }

    /// Evaluate a price delta tick against the pre-computed trigger thresholds.
    ///
    /// This is the **hottest function in the entire codebase** — called on every
    /// Binance aggTrade message. Every operation is O(1): atomic loads and
    /// arithmetic comparisons only. No allocation, no lock, no syscall.
    ///
    /// # Returns
    /// `Some(Direction)` if a threshold was crossed and the sniper is armed.
    /// `None` if no threshold was crossed or the sniper is not armed.
    ///
    /// # Caller responsibility
    /// The caller must have already checked:
    ///   1. `!is_market_expired(ts)`
    ///   2. `seconds_to_expiry(ts) > 15.0`  (no new positions near expiry)
    #[inline]
    pub fn evaluate_delta(&self, delta: f64) -> Option<Direction> {
        if !self.sniper.is_armed() {
            return None;
        }
        // Both loads use `Acquire` so we see the latest `Release` write from
        // SituationRoom, which runs on a different thread.
        let trig_up   = self.sniper.trigger_up.load(Ordering::Acquire);
        let trig_down = self.sniper.trigger_down.load(Ordering::Acquire);

        if delta >= trig_up {
            // Atomically disarm — prevents two consecutive ticks both triggering.
            if self.sniper.try_disarm() {
                return Some(Direction::Up);
            }
        } else if delta <= -trig_down {
            if self.sniper.try_disarm() {
                return Some(Direction::Down);
            }
        }
        None
    }

    /// Publish a new [`MarketInfo`] atomically.
    ///
    /// This is an O(1) pointer swap — readers on any thread will see the new
    /// info on their very next `market.load()` call.
    pub fn publish_market(&self, info: MarketInfo) {
        let expiry = info.expiry_ts;
        self.market.store(Some(Arc::new(info)));
        // Release: ensures all readers that subsequently load market_expiry
        // with Acquire also see the new MarketInfo pointer.
        self.market_expiry.store(expiry, Ordering::Release);
    }

    /// Get a clone of the EV breakdown strings for the given direction.
    ///
    /// Uses a short `RwLock` read — called only when a trade fires (rare).
    pub fn ev_breakdown(&self, direction: Direction) -> String {
        let diag = self.situation_diag.read();
        match direction {
            Direction::Up   => diag.last_breakdown_up.clone(),
            Direction::Down => diag.last_breakdown_down.clone(),
        }
    }

    /// Update EV breakdown strings. Called by SituationRoom every 500ms.
    pub fn update_situation_diag(&self, up: String, down: String) {
        let mut diag = self.situation_diag.write();
        diag.last_breakdown_up   = up;
        diag.last_breakdown_down = down;
    }
}

impl Default for SharedState {
    fn default() -> Self {
        // Delegate to new(), but without the Arc wrapper.
        // This exists to satisfy trait bounds; prefer `SharedState::new()`.
        Self {
            market:           ArcSwapOption::empty(),
            market_expiry:    AtomicU64::new(0),
            is_rolling_over:  AtomicBool::new(false),
            poly_disconnect:  Notify::new(),
            poly_reconnect:   Notify::new(),
            binance:          BinanceAtomicState::new(),
            book:             OrderBookAtomicState::new(),
            sniper:           SniperAtomicState::new(),
            situation_diag:   parking_lot::RwLock::new(SituationRoomDiagnostics::default()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// handle_rollover — the async rollover coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Coordinates a full market rollover when the current window expires.
///
/// This is spawned as a new `tokio::task` the instant a Binance tick reveals
/// that the current market has expired. It runs concurrently with (but isolated
/// from) the Binance WS loop, which continues to receive and drop expired
/// messages while rollover is in progress.
///
/// # Rollover sequence (mirrors Python `handle_rollover`)
///
/// See [`SharedState`] doc for the numbered sequence.
///
/// # Panics
/// Never panics — all errors are logged and the rollover flag is cleared so
/// the bot can attempt recovery on the next tick.
pub async fn handle_rollover(
    state: Arc<SharedState>,
    market_fetcher: Arc<crate::market_fetcher::MarketFetcher>,
) {
    info!("🔄 Market expired — initiating rollover sequence...");

    // ── Step a: Disarm immediately so no new trades can fire. ─────────────────
    state.sniper.is_armed.store(false, Ordering::Release);

    // ── Step b: Signal the Polymarket WS task to exit its message loop. ───────
    state.poly_disconnect.notify_one();

    // Yield once to let the Polymarket WS task observe the notification before
    // we wipe its state. This is advisory, not required for correctness (the
    // state reset is safe because the WS task stops writing on disconnect).
    tokio::task::yield_now().await;

    // ── Steps c-e: Reset all in-memory market state. ──────────────────────────
    state.book.reset();
    state.binance.reset();
    state.sniper.reset_for_new_window();

    info!("State wiped. Fetching new market from Gamma API...");

    // ── Step f: Fetch the new market (async HTTP, may retry internally). ──────
    let result = market_fetcher.update_market(true).await;

    // ── Steps g-k: Publish new market or log failure. ─────────────────────────
    match result {
        Ok(info) => {
            info!(
                token_up   = %info.token_id_up,
                token_down = %info.token_id_down,
                expiry_ts  = info.expiry_ts,
                "✅ New market resolved — publishing atomically."
            );

            // g + h: Atomically publish new MarketInfo and update expiry.
            state.publish_market(info);

            // i: Signal the Polymarket WS task to reconnect with new token IDs.
            state.poly_reconnect.notify_one();

            // j: Re-arm the sniper.
            state.sniper.arm();

            info!("🎯 Rollover complete. Sniper is ARMED on new market.");
        }
        Err(e) => {
            error!(
                error = %e,
                "❌ Failed to fetch new market during rollover. \
                 Will retry on next tick. Sniper remains DISARMED."
            );
            // We deliberately leave is_armed = false and market as the old (now
            // expired) snapshot. The next Binance tick will detect is_rolling_over
            // = false again (see step k) and the sniper will stay disarmed.
            // The position manager can still manage open positions.
        }
    }

    // ── Step k: Clear the rollover lock LAST. ─────────────────────────────────
    // Release ordering: all prior stores (market_expiry, is_armed) are visible
    // to any thread that subsequently loads is_rolling_over with Acquire.
    state.is_rolling_over.store(false, Ordering::Release);
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: current Unix timestamp in seconds (f64)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the current wall-clock time as seconds since UNIX epoch.
///
/// Used ONLY in non-hot-path code (startup, rollover logic, position manager).
/// The hot path uses the **exchange-provided timestamp** from the Binance
/// WebSocket message (`msg["E"] / 1000`) to avoid OS syscalls on every tick.
#[inline]
pub fn unix_now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64()
}

/// Compute the next market window's expiry timestamp given the current time.
///
/// Mirrors the Python `MarketFetcher.update_market` window calculation:
/// ```text
/// window_ts = (now // window_secs) * window_secs
/// expiry    = window_ts + window_secs
/// ```
pub fn compute_next_expiry(now_secs: u64, window_secs: u64) -> u64 {
    let window_ts = (now_secs / window_secs) * window_secs;
    window_ts + window_secs
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper to force-initialise CONFIG in test context. ───────────────────
    fn init() {
        // Touch CONFIG to trigger the Lazy initialiser (uses all defaults).
        let _ = CONFIG.paper_mode;
    }

    // ── OrderBookSnapshot::effective_ask ─────────────────────────────────────

    #[test]
    fn effective_ask_uses_real_when_better() {
        let snap = OrderBookSnapshot {
            best_ask:     Some(0.55),
            best_bid:     Some(0.50),
            opposing_bid: Some(0.40), // synthetic = 1.0 - 0.40 = 0.60
        };
        // Real (0.55) < synthetic (0.60) → use real
        assert_eq!(snap.effective_ask(), Some(0.55));
    }

    #[test]
    fn effective_ask_uses_synthetic_when_better() {
        let snap = OrderBookSnapshot {
            best_ask:     Some(0.70),
            best_bid:     Some(0.65),
            opposing_bid: Some(0.35), // synthetic = 0.65
        };
        // Synthetic (0.65) < real (0.70) → use synthetic
        assert_eq!(snap.effective_ask(), Some(0.65));
    }

    #[test]
    fn effective_ask_fallback_to_synthetic_when_no_real() {
        let snap = OrderBookSnapshot {
            best_ask:     None,
            best_bid:     None,
            opposing_bid: Some(0.42), // synthetic = 0.58
        };
        assert!((snap.effective_ask().unwrap() - 0.58_f64).abs() < 1e-9);
    }

    #[test]
    fn effective_ask_returns_none_when_both_missing() {
        let snap = OrderBookSnapshot {
            best_ask:     None,
            best_bid:     None,
            opposing_bid: None,
        };
        assert_eq!(snap.effective_ask(), None);
    }

    #[test]
    fn effective_ask_ignores_zero_opposing_bid() {
        let snap = OrderBookSnapshot {
            best_ask:     Some(0.60),
            best_bid:     Some(0.55),
            opposing_bid: Some(0.0), // zero bid → ignore synthetic
        };
        assert_eq!(snap.effective_ask(), Some(0.60));
    }

    // ── spread ────────────────────────────────────────────────────────────────

    #[test]
    fn spread_computed_correctly() {
        let snap = OrderBookSnapshot {
            best_ask:     Some(0.55),
            best_bid:     Some(0.52),
            opposing_bid: None,
        };
        assert!((snap.spread().unwrap() - 0.03_f64).abs() < 1e-9);
    }

    #[test]
    fn spread_none_when_ask_missing() {
        let snap = OrderBookSnapshot {
            best_ask:     None,
            best_bid:     Some(0.50),
            opposing_bid: None,
        };
        assert_eq!(snap.spread(), None);
    }

    // ── load_price / store_price ──────────────────────────────────────────────

    #[test]
    fn price_sentinel_round_trips() {
        let a = AtomicF64::new(NO_PRICE);
        assert_eq!(load_price(&a, Ordering::Relaxed), None);

        store_price(&a, Some(0.75), Ordering::Relaxed);
        assert_eq!(load_price(&a, Ordering::Relaxed), Some(0.75));

        store_price(&a, None, Ordering::Relaxed);
        assert_eq!(load_price(&a, Ordering::Relaxed), None);
    }

    #[test]
    fn price_zero_treated_as_none() {
        let a = AtomicF64::new(0.0);
        assert_eq!(load_price(&a, Ordering::Relaxed), None);
    }

    #[test]
    fn negative_price_stored_as_none() {
        let a = AtomicF64::new(NO_PRICE);
        store_price(&a, Some(-0.5), Ordering::Relaxed);
        assert_eq!(load_price(&a, Ordering::Relaxed), None);
    }

    // ── BinanceAtomicState::update ────────────────────────────────────────────

    #[test]
    fn binance_cold_start_seeds_ema_with_first_price() {
        let s = BinanceAtomicState::new();
        let delta = s.update(100.0, 1_000.0, 2.0);
        // On cold start: ema = price, delta = price - ema = 0
        assert!((delta).abs() < 1e-9);
        assert!((s.ema_price.load(Ordering::Relaxed) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn binance_ema_decays_toward_new_price() {
        let s = BinanceAtomicState::new();
        // Seed with 100 at t=1000 (non-zero so NaN sentinel is cleared correctly).
        s.update(100.0, 1_000.0, 2.0);
        // Now a tick at t=1001: delta_t = 1.0, alpha = min(1, 1/2) = 0.5
        // ema = 200*0.5 + 100*0.5 = 150; delta = 200 - 150 = 50
        let delta = s.update(200.0, 1_001.0, 2.0);
        assert!((delta - 50.0).abs() < 1e-9);
    }

    #[test]
    fn binance_reset_zeros_all_fields() {
        let s = BinanceAtomicState::new();
        s.update(100.0, 1_000.0, 2.0);
        s.reset();
        assert_eq!(s.ema_price.load(Ordering::Relaxed), 0.0);
        // After reset, last_ts must be NaN (the cold-start sentinel).
        assert!(s.last_ts.load(Ordering::Relaxed).is_nan(),
            "last_ts should be NaN after reset, not 0.0");
        assert_eq!(s.price_delta.load(Ordering::Relaxed), 0.0);
        assert_eq!(s.current_price.load(Ordering::Relaxed), 0.0);
    }

    // ── SniperAtomicState ─────────────────────────────────────────────────────

    #[test]
    fn sniper_try_disarm_is_atomic_cas() {
        init();
        let s = SniperAtomicState::new();
        s.arm();
        assert!(s.try_disarm());   // First CAS succeeds
        assert!(!s.try_disarm());  // Second CAS fails — already disarmed
    }

    #[test]
    fn sniper_shots_increment_correctly() {
        init();
        let s = SniperAtomicState::new();
        assert_eq!(s.increment_shots(), 1);
        assert_eq!(s.increment_shots(), 2);
        assert_eq!(s.increment_shots(), 3);
    }

    #[test]
    fn sniper_reset_clears_shots_and_thresholds() {
        init();
        let s = SniperAtomicState::new();
        s.increment_shots();
        s.set_triggers(10.0, 20.0);
        s.reset_for_new_window();
        assert_eq!(s.window_shots_fired.load(Ordering::Relaxed), 0);
        // Triggers should be reset to f64::MAX
        assert_eq!(s.trigger_up.load(Ordering::Relaxed), f64::MAX);
        assert_eq!(s.trigger_down.load(Ordering::Relaxed), f64::MAX);
        // Dynamic threshold should be reset to CONFIG base
        let expected = CONFIG.momentum_threshold_usd;
        assert!((s.current_dynamic_threshold.load(Ordering::Relaxed) - expected).abs() < 1e-9);
    }

    // ── SharedState::evaluate_delta ───────────────────────────────────────────

    #[test]
    fn evaluate_delta_returns_none_when_disarmed() {
        init();
        let state = SharedState::new();
        // Sniper starts disarmed — even a huge delta must be rejected.
        state.sniper.set_triggers(1.0, 1.0);
        assert_eq!(state.evaluate_delta(9999.0), None);
    }

    #[test]
    fn evaluate_delta_detects_up_signal() {
        init();
        let state = SharedState::new();
        state.sniper.arm();
        state.sniper.set_triggers(40.0, 40.0);
        assert_eq!(state.evaluate_delta(50.0), Some(Direction::Up));
    }

    #[test]
    fn evaluate_delta_detects_down_signal() {
        init();
        let state = SharedState::new();
        state.sniper.arm();
        state.sniper.set_triggers(40.0, 40.0);
        assert_eq!(state.evaluate_delta(-50.0), Some(Direction::Down));
    }

    #[test]
    fn evaluate_delta_disarms_after_trigger() {
        init();
        let state = SharedState::new();
        state.sniper.arm();
        state.sniper.set_triggers(40.0, 40.0);
        let first  = state.evaluate_delta(50.0);
        let second = state.evaluate_delta(50.0); // Should be None — already disarmed
        assert_eq!(first,  Some(Direction::Up));
        assert_eq!(second, None);
    }

    #[test]
    fn evaluate_delta_no_trigger_below_threshold() {
        init();
        let state = SharedState::new();
        state.sniper.arm();
        state.sniper.set_triggers(40.0, 40.0);
        assert_eq!(state.evaluate_delta(39.9), None);
        assert_eq!(state.evaluate_delta(-39.9), None);
    }

    // ── SharedState::is_market_expired ────────────────────────────────────────

    #[test]
    fn market_expiry_check_returns_false_before_expiry() {
        let state = SharedState::new();
        state.market_expiry.store(2_000_000_000, Ordering::Relaxed);
        assert!(!state.is_market_expired(1_999_999_999.0));
    }

    #[test]
    fn market_expiry_check_returns_true_at_expiry() {
        let state = SharedState::new();
        state.market_expiry.store(2_000_000_000, Ordering::Relaxed);
        assert!(state.is_market_expired(2_000_000_000.0));
    }

    #[test]
    fn market_expiry_check_returns_false_when_zero() {
        // expiry = 0 means no market loaded yet — should not trigger rollover.
        let state = SharedState::new();
        assert!(!state.is_market_expired(0.0));
        assert!(!state.is_market_expired(9_999_999_999.0));
    }

    // ── compute_next_expiry ───────────────────────────────────────────────────

    #[test]
    fn compute_next_expiry_aligns_to_window() {
        // 15-minute window = 900 seconds
        // If now = 1_750_000_050, window_ts = floor(1_750_000_050 / 900) * 900
        // = 1_750_000_800 / 900 ... let's compute:
        // 1_750_000_050 / 900 = 1944444 (integer), * 900 = 1_749_999_600
        // expiry = 1_749_999_600 + 900 = 1_750_000_500
        let now    = 1_750_000_050_u64;
        let window = 900_u64;
        let expiry = compute_next_expiry(now, window);
        assert_eq!(expiry, 1_750_000_500);
        // expiry must be > now and <= now + window
        assert!(expiry > now);
        assert!(expiry <= now + window);
    }

    #[test]
    fn compute_next_expiry_exactly_on_boundary() {
        // If now is exactly on a boundary, the current window just started,
        // so expiry = boundary + window.
        // 1_750_000_500 / 900 = 1_944_445 exactly → it IS a valid boundary.
        let window   = 900_u64;
        let boundary = 1_750_000_500_u64; // 1_944_445 * 900 — truly divisible by 900
        let expiry   = compute_next_expiry(boundary, window);
        // window_ts = (boundary / window) * window = boundary (no rounding)
        // expiry    = boundary + window
        assert_eq!(expiry, boundary + window,
            "boundary={} / window={} should give expiry={}",
            boundary, window, boundary + window);
        // Sanity check: boundary must be divisible by window.
        assert_eq!(boundary % window, 0, "test boundary must be divisible by window");
    }

    // ── Direction ─────────────────────────────────────────────────────────────

    #[test]
    fn direction_opposite_is_symmetric() {
        assert_eq!(Direction::Up.opposite(), Direction::Down);
        assert_eq!(Direction::Down.opposite(), Direction::Up);
    }

    #[test]
    fn direction_display() {
        assert_eq!(format!("{}", Direction::Up),   "UP");
        assert_eq!(format!("{}", Direction::Down), "DOWN");
    }

    // ── MarketInfo::publish round-trip ────────────────────────────────────────

    #[test]
    fn publish_market_updates_expiry_atomically() {
        let state = SharedState::new();
        let info = MarketInfo {
            token_id_up:   "UP_TOKEN".into(),
            token_id_down: "DOWN_TOKEN".into(),
            market_id:     "12345".into(),
            market_slug:   "btc-updown-15m-1749999600".into(),
            condition_id:  "0xABC".into(),
            expiry_ts:     1_750_000_500,
            neg_risk:      true,
        };
        state.publish_market(info);
        assert_eq!(state.market_expiry.load(Ordering::Acquire), 1_750_000_500);

        let guard = state.market.load();
        let loaded = guard.as_ref().expect("market should be Some after publish");
        assert_eq!(loaded.token_id_up, "UP_TOKEN");
        assert_eq!(loaded.expiry_ts, 1_750_000_500);
    }
}
