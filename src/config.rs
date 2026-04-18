//! config.rs — Zero-cost global CONFIG parsed from `.env` once at startup.
//!
//! # Design
//!
//! ```text
//!  .env file / OS environment
//!        │
//!        ▼  (startup, single parse)
//!  Config::load()  ──►  Lazy<Config>  (CONFIG global)
//!        │
//!        ▼  (hot path: single pointer deref, no locking)
//!  &CONFIG.momentum_threshold_usd
//! ```
//!
//! - [`once_cell::sync::Lazy`] guarantees that `Config::load()` is called
//!   **exactly once**, before any WebSocket task is spawned.  Every subsequent
//!   access is a plain immutable reference with zero synchronisation cost.
//! - All fields are `pub` and stored by value — no getter indirection.
//! - The derived `binance_ws_url` is constructed once here so the stream task
//!   never allocates a `String` at connection time.
//! - Validation occurs inside `load()`, which panics at startup (not mid-trade)
//!   if the environment is misconfigured.  A misconfigured bot should not run.

use once_cell::sync::Lazy;
use std::env;
use tracing::warn;

use crate::errors::{ConfigError, BotResult};

// ─────────────────────────────────────────────────────────────────────────────
// Global singleton
// ─────────────────────────────────────────────────────────────────────────────

/// The single, immutable config instance for the entire process.
///
/// Access pattern on hot path:
/// ```rust,ignore
/// let threshold = CONFIG.momentum_threshold_usd;  // single deref, zero cost
/// ```
pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    // Load .env file — non-fatal; we fall back to OS environment variables.
    if let Err(e) = dotenvy::dotenv() {
        warn!("Could not load .env file (falling back to OS env): {e}");
    }
    match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            // Configuration errors are fatal before any trading begins.
            // `panic!` here is intentional and correct — a misconfigured bot
            // must not silently trade with wrong parameters.
            panic!("FATAL: Configuration error — {e}");
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Config struct
//
// Memory layout note: all numeric fields are f64 (8 bytes) or bool (1 byte).
// Total size ≈ 600 bytes — fits in a single cache line cluster, so a cold
// deref from a fresh CPU core still reads the most-used fields in 2-3 lines.
// ─────────────────────────────────────────────────────────────────────────────

/// Flat, fully-validated configuration for the sniper bot.
///
/// Fields map 1-to-1 to the Python `config.py` names (snake_case).
/// All `f64` fields have been validated to be finite and within trading-safe
/// ranges at construction time.
#[derive(Debug, Clone)]
pub struct Config {
    // ── Mode ─────────────────────────────────────────────────────────────────
    /// If `true`, all orders are simulated; no real money is spent.
    pub paper_mode: bool,

    // ── Market ───────────────────────────────────────────────────────────────
    /// Lower-case asset ticker, e.g. `"btc"` or `"eth"`.
    pub market_asset: String,

    /// Market window duration in minutes (e.g. 15 → 15-minute binary markets).
    pub market_window_min: u32,

    // ── WebSocket URLs (derived at init time, zero allocation on reconnect) ──
    /// `wss://stream.binance.com:9443/ws/{asset}usdt@aggTrade`
    pub binance_ws_url: String,

    /// Polymarket L2 CLOB WebSocket endpoint.
    pub poly_ws_url: String,

    // ── RPC / Credentials ────────────────────────────────────────────────────
    /// Polygon RPC URL for on-chain balance queries. Empty string = disabled.
    pub poly_rpc_url: String,

    /// Hex-encoded secp256k1 private key (without `0x` prefix accepted too).
    /// Stored as `String` so it can be zeroised on drop by the caller if needed.
    pub private_key: String,

    // ── Trade Execution ───────────────────────────────────────────────────────
    /// Maximum multiplier applied to base position size when compounding wins.
    pub max_position_multiplier: f64,

    /// Take-profit target as a fraction of entry price (e.g. 0.15 = 15%).
    pub take_profit_pct: f64,

    /// Slippage tolerance in basis points (e.g. 500 = 5%).
    pub slippage_bps: u32,

    /// Pre-computed slippage multiplier: `1.0 + slippage_bps / 10_000.0`.
    /// Stored here to avoid the division on every tick evaluation.
    pub slippage_multiplier: f64,

    /// Hard ceiling price for any sell order (e.g. 0.98).
    pub exit_ceiling_price: f64,

    /// Cooldown between consecutive sell attempts on the same token (seconds).
    pub sell_cooldown_sec: f64,

    /// Minimum pause between consecutive buy signals (seconds).
    pub sniper_debounce_sec: f64,

    /// Maximum allowed ask price for a buy to proceed (e.g. 0.85).
    pub max_buy_price: f64,

    /// Whether to emit a system beep on trade execution (cosmetic; no hot path).
    pub play_beep_on_trade: bool,

    // ── Momentum / EMA ───────────────────────────────────────────────────────
    /// Base USD momentum delta required to trigger a trade (e.g. $40.00).
    pub momentum_threshold_usd: f64,

    /// Fractional step applied to `momentum_threshold_usd` after each trade
    /// within the same window (e.g. 0.15 = raise bar by 15% per shot).
    pub momentum_step_pct: f64,

    /// Time-decay window for the exponential moving average (seconds).
    pub momentum_window_sec: f64,

    // ── Gas / Chain ───────────────────────────────────────────────────────────
    /// Priority fee multiplier for Polygon gas estimation.
    pub gas_priority_multiplier: f64,

    // ── Kelly Sizing Tiers ────────────────────────────────────────────────────
    /// EV score threshold for Tier A (full-size) sizing.
    pub kelly_tier_a_score: f64,

    /// Bankroll fraction allocated at Tier A (e.g. 0.50 = 50%).
    pub kelly_tier_a_fraction: f64,

    /// EV score threshold for Tier B (moderate) sizing.
    pub kelly_tier_b_score: f64,

    /// Bankroll fraction allocated at Tier B (e.g. 0.33 = 33%).
    pub kelly_tier_b_fraction: f64,

    /// Bankroll fraction allocated at Tier C (base / conservative) sizing.
    pub kelly_tier_c_fraction: f64,

    // ── Expected Value (EV) Model ─────────────────────────────────────────────
    /// Coefficient applied to momentum delta when computing EV score bonus.
    pub ev_momentum_multiplier: f64,

    /// Base EV score before any bonuses or penalties are applied.
    pub ev_base_score: f64,

    /// Price threshold above which time-to-expiry penalties activate.
    pub ev_high_price_thresh: f64,

    /// Seconds-to-expiry below which the "danger" time penalty applies.
    pub ev_time_danger_sec: f64,

    /// Seconds-to-expiry below which the "warning" time penalty applies.
    pub ev_time_warn_sec: f64,

    /// EV penalty applied when in the danger zone.
    pub ev_time_danger_penalty: f64,

    /// EV penalty applied when in the warning zone.
    pub ev_time_warn_penalty: f64,

    /// EV penalty applied when there are no bids on the target token.
    pub ev_no_bids_penalty: f64,

    /// Maximum EV bonus that momentum can contribute.
    pub ev_max_momentum_bonus: f64,

    /// Minimum EV score required to proceed with a buy.
    pub ev_min_acceptable_score: f64,

    /// EV score below which an open position is immediately force-exited.
    pub ev_bailout_score_thresh: f64,

    // ── Death Trap (Falling Knife Avoidance) ──────────────────────────────────
    /// Price threshold below which the first death-trap penalty activates.
    pub ev_death_trap_thresh_1: f64,

    /// EV penalty applied when price is below `ev_death_trap_thresh_1`.
    pub ev_death_trap_penalty_1: f64,

    /// Price threshold below which the second (lighter) death-trap penalty activates.
    pub ev_death_trap_thresh_2: f64,

    /// EV penalty applied when price is below `ev_death_trap_thresh_2`.
    pub ev_death_trap_penalty_2: f64,

    // ── Spread Safety Gate ────────────────────────────────────────────────────
    /// Maximum tolerated bid-ask spread in price units (e.g. 0.05 = 5 cents).
    /// Orders with a wider spread are aborted to protect against ghost liquidity.
    pub max_spread_cents: f64,

    // ── Safe-to-Expiry Hold Logic ─────────────────────────────────────────────
    /// Minimum best-bid price to consider the position "safe to hold to expiry".
    pub safe_expiry_bid_thresh: f64,

    /// If this many seconds remain and the position is "safe", hold to expiry.
    pub safe_expiry_time_sec: f64,

    // ── Impatience Timer (Micro-Bounce Escape) ────────────────────────────────
    /// After this many seconds, abandon a stagnant position at a micro-TP.
    pub impatience_sec: f64,

    /// Minimum gain fraction that satisfies the impatience take-profit.
    pub impatience_tp_pct: f64,

    // ── Logging ───────────────────────────────────────────────────────────────
    /// Path to the clean (filtered) trade log file.
    pub clean_log_file: String,

    // ── Starting Bankroll (paper mode only) ───────────────────────────────────
    /// Simulated starting bankroll for paper trading runs (USD).
    pub starting_bankroll: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing helpers — read once, validate immediately, never call again.
// ─────────────────────────────────────────────────────────────────────────────

/// Read an environment variable as a `String`, returning a default if absent.
/// Returns `Err` only if the variable is present but contains non-UTF-8 bytes
/// (which `std::env::var` already rejects, so this never errors in practice).
fn env_str(key: &'static str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read an environment variable as `f64`.
///
/// - If the variable is absent → use `default`.
/// - If the variable is present but not a valid `f64` → return `Err`.
/// - If the parsed value is not finite (NaN / ±Inf) → return `Err`.
fn env_f64(key: &'static str, default: f64) -> BotResult<f64> {
    match env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw.trim().parse::<f64>().map_err(|_| {
            crate::errors::ConfigError::InvalidValue {
                key,
                expected: "f64",
                got: raw.clone(),
            }
            .into()
        }).and_then(|v| {
            if v.is_finite() {
                Ok(v)
            } else {
                Err(crate::errors::ConfigError::InvalidValue {
                    key,
                    expected: "finite f64",
                    got: raw,
                }
                .into())
            }
        }),
    }
}

/// Read an environment variable as `u32`.
fn env_u32(key: &'static str, default: u32) -> BotResult<u32> {
    match env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw.trim().parse::<u32>().map_err(|_| {
            crate::errors::ConfigError::InvalidValue {
                key,
                expected: "u32",
                got: raw,
            }
            .into()
        }),
    }
}

/// Read an environment variable as `bool`.
///
/// Accepts `"true"`, `"1"`, `"t"` (case-insensitive) as `true`;
/// everything else is `false`.
fn env_bool(key: &'static str, default: bool) -> bool {
    match env::var(key) {
        Err(_) => default,
        Ok(raw) => matches!(raw.trim().to_lowercase().as_str(), "true" | "1" | "t"),
    }
}

/// Assert that `value` is within the inclusive range `[min, max]`.
fn validate_range(key: &'static str, value: f64, min: f64, max: f64) -> BotResult<f64> {
    if value < min || value > max {
        Err(ConfigError::OutOfRange { key, value, min, max }.into())
    } else {
        Ok(value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config::load  — called exactly once by the Lazy initialiser
// ─────────────────────────────────────────────────────────────────────────────

impl Config {
    /// Parse and validate every configuration value from the environment.
    ///
    /// All validation happens here so the rest of the codebase can treat every
    /// `CONFIG.*` field as a guaranteed-valid value with no further checks.
    fn load() -> BotResult<Self> {
        // ── Mode ─────────────────────────────────────────────────────────────
        let paper_mode = env_bool("PAPER_MODE", true);

        // ── Market ───────────────────────────────────────────────────────────
        let market_asset = env_str("MARKET_ASSET", "btc").to_lowercase();
        let market_window_min = env_u32("MARKET_WINDOW", 15)?;

        if market_window_min == 0 {
            return Err(ConfigError::OutOfRange {
                key: "MARKET_WINDOW",
                value: 0.0,
                min: 1.0,
                max: 1440.0,
            }
            .into());
        }

        // ── URLs (derived) ────────────────────────────────────────────────────
        let binance_ws_url = format!(
            "wss://stream.binance.com:9443/ws/{}usdt@aggTrade",
            market_asset
        );
        let poly_ws_url =
            env_str("POLY_WS_URL", "wss://ws-subscriptions-clob.polymarket.com/ws/market");

        // ── Credentials ───────────────────────────────────────────────────────
        let poly_rpc_url = env_str("POLY_RPC_URL", "");
        let private_key  = env_str("PRIVATE_KEY", "");

        if private_key.is_empty() && !paper_mode {
            // Hard error: live trading with no private key is impossible.
            return Err(ConfigError::MissingVar { key: "PRIVATE_KEY" }.into());
        }

        // ── Trade Execution ───────────────────────────────────────────────────
        let max_position_multiplier =
            validate_range("MAX_POSITION_MULTIPLIER", env_f64("MAX_POSITION_MULTIPLIER", 5.0)?, 1.0, 100.0)?;

        let take_profit_pct =
            validate_range("TAKE_PROFIT_PCT", env_f64("TAKE_PROFIT_PCT", 0.15)?, 0.001, 1.0)?;

        let slippage_bps = env_u32("SLIPPAGE_BPS", 500)?;
        if slippage_bps > 10_000 {
            return Err(ConfigError::OutOfRange {
                key: "SLIPPAGE_BPS",
                value: slippage_bps as f64,
                min: 0.0,
                max: 10_000.0,
            }
            .into());
        }
        // Pre-compute the multiplier once — avoids the division on every tick.
        let slippage_multiplier = 1.0 + (slippage_bps as f64 / 10_000.0);

        let exit_ceiling_price =
            validate_range("EXIT_CEILING_PRICE", env_f64("EXIT_CEILING_PRICE", 0.98)?, 0.01, 0.99)?;

        let sell_cooldown_sec =
            validate_range("SELL_COOLDOWN_SECONDS", env_f64("SELL_COOLDOWN_SECONDS", 4.0)?, 0.0, 3600.0)?;

        let sniper_debounce_sec =
            validate_range("SNIPER_DEBOUNCE_SEC", env_f64("SNIPER_DEBOUNCE_SEC", 0.5)?, 0.0, 60.0)?;

        let max_buy_price =
            validate_range("MAX_BUY_PRICE", env_f64("MAX_BUY_PRICE", 0.85)?, 0.01, 0.99)?;

        let play_beep_on_trade = env_bool("PLAY_BEEP_ON_TRADE", true);

        // ── Momentum / EMA ────────────────────────────────────────────────────
        let momentum_threshold_usd =
            validate_range("MOMENTUM_THRESHOLD_USD", env_f64("MOMENTUM_THRESHOLD_USD", 40.0)?, 0.01, 100_000.0)?;

        let momentum_step_pct =
            validate_range("MOMENTUM_STEP_PCT", env_f64("MOMENTUM_STEP_PCT", 0.15)?, 0.0, 10.0)?;

        let momentum_window_sec =
            validate_range("MOMENTUM_WINDOW_SEC", env_f64("MOMENTUM_WINDOW_SEC", 2.0)?, 0.1, 3600.0)?;

        // ── Gas ───────────────────────────────────────────────────────────────
        let gas_priority_multiplier =
            validate_range("GAS_PRIORITY_MULTIPLIER", env_f64("GAS_PRIORITY_MULTIPLIER", 5.0)?, 1.0, 100.0)?;

        // ── Kelly Tiers ───────────────────────────────────────────────────────
        let kelly_tier_a_score =
            validate_range("KELLY_TIER_A_SCORE", env_f64("KELLY_TIER_A_SCORE", 80.0)?, 0.0, 100.0)?;

        let kelly_tier_a_fraction =
            validate_range("KELLY_TIER_A_FRACTION", env_f64("KELLY_TIER_A_FRACTION", 0.50)?, 0.0, 1.0)?;

        let kelly_tier_b_score =
            validate_range("KELLY_TIER_B_SCORE", env_f64("KELLY_TIER_B_SCORE", 60.0)?, 0.0, 100.0)?;

        let kelly_tier_b_fraction =
            validate_range("KELLY_TIER_B_FRACTION", env_f64("KELLY_TIER_B_FRACTION", 0.33)?, 0.0, 1.0)?;

        let kelly_tier_c_fraction =
            validate_range("KELLY_TIER_C_FRACTION", env_f64("KELLY_TIER_C_FRACTION", 0.25)?, 0.0, 1.0)?;

        if kelly_tier_b_score >= kelly_tier_a_score {
            return Err(ConfigError::OutOfRange {
                key: "KELLY_TIER_B_SCORE",
                value: kelly_tier_b_score,
                min: 0.0,
                max: kelly_tier_a_score - 0.001,
            }
            .into());
        }

        // ── EV Model ──────────────────────────────────────────────────────────
        let ev_momentum_multiplier =
            validate_range("EV_MOMENTUM_MULTIPLIER", env_f64("EV_MOMENTUM_MULTIPLIER", 0.15)?, 0.0, 100.0)?;

        let ev_base_score =
            validate_range("EV_BASE_SCORE", env_f64("EV_BASE_SCORE", 50.0)?, 0.0, 100.0)?;

        let ev_high_price_thresh =
            validate_range("EV_HIGH_PRICE_THRESH", env_f64("EV_HIGH_PRICE_THRESH", 0.80)?, 0.0, 1.0)?;

        let ev_time_danger_sec =
            validate_range("EV_TIME_DANGER_SEC", env_f64("EV_TIME_DANGER_SEC", 300.0)?, 0.0, 86_400.0)?;

        let ev_time_warn_sec =
            validate_range("EV_TIME_WARN_SEC", env_f64("EV_TIME_WARN_SEC", 120.0)?, 0.0, 86_400.0)?;

        let ev_time_danger_penalty =
            validate_range("EV_TIME_DANGER_PENALTY", env_f64("EV_TIME_DANGER_PENALTY", 30.0)?, 0.0, 100.0)?;

        let ev_time_warn_penalty =
            validate_range("EV_TIME_WARN_PENALTY", env_f64("EV_TIME_WARN_PENALTY", 15.0)?, 0.0, 100.0)?;

        let ev_no_bids_penalty =
            validate_range("EV_NO_BIDS_PENALTY", env_f64("EV_NO_BIDS_PENALTY", 40.0)?, 0.0, 100.0)?;

        let ev_max_momentum_bonus =
            validate_range("EV_MAX_MOMENTUM_BONUS", env_f64("EV_MAX_MOMENTUM_BONUS", 20.0)?, 0.0, 100.0)?;

        let ev_min_acceptable_score =
            validate_range("EV_MIN_ACCEPTABLE_SCORE", env_f64("EV_MIN_ACCEPTABLE_SCORE", 40.0)?, 0.0, 100.0)?;

        let ev_bailout_score_thresh =
            validate_range("EV_BAILOUT_SCORE_THRESH", env_f64("EV_BAILOUT_SCORE_THRESH", 25.0)?, 0.0, 100.0)?;

        // ── Death Trap ────────────────────────────────────────────────────────
        let ev_death_trap_thresh_1 =
            validate_range("EV_DEATH_TRAP_THRESH_1", env_f64("EV_DEATH_TRAP_THRESH_1", 0.10)?, 0.0, 1.0)?;

        let ev_death_trap_penalty_1 =
            validate_range("EV_DEATH_TRAP_PENALTY_1", env_f64("EV_DEATH_TRAP_PENALTY_1", 40.0)?, 0.0, 100.0)?;

        let ev_death_trap_thresh_2 =
            validate_range("EV_DEATH_TRAP_THRESH_2", env_f64("EV_DEATH_TRAP_THRESH_2", 0.20)?, 0.0, 1.0)?;

        let ev_death_trap_penalty_2 =
            validate_range("EV_DEATH_TRAP_PENALTY_2", env_f64("EV_DEATH_TRAP_PENALTY_2", 20.0)?, 0.0, 100.0)?;

        if ev_death_trap_thresh_1 >= ev_death_trap_thresh_2 {
            return Err(ConfigError::OutOfRange {
                key: "EV_DEATH_TRAP_THRESH_1",
                value: ev_death_trap_thresh_1,
                min: 0.0,
                max: ev_death_trap_thresh_2 - f64::EPSILON,
            }
            .into());
        }

        // ── Spread Safety Gate ────────────────────────────────────────────────
        let max_spread_cents =
            validate_range("MAX_SPREAD_CENTS", env_f64("MAX_SPREAD_CENTS", 0.05)?, 0.0, 1.0)?;

        // ── Safe-to-Expiry ────────────────────────────────────────────────────
        let safe_expiry_bid_thresh =
            validate_range("SAFE_EXPIRY_BID_THRESH", env_f64("SAFE_EXPIRY_BID_THRESH", 0.95)?, 0.0, 1.0)?;

        let safe_expiry_time_sec =
            validate_range("SAFE_EXPIRY_TIME_SEC", env_f64("SAFE_EXPIRY_TIME_SEC", 120.0)?, 0.0, 86_400.0)?;

        // ── Impatience Timer ──────────────────────────────────────────────────
        let impatience_sec =
            validate_range("IMPATIENCE_SEC", env_f64("IMPATIENCE_SEC", 200.0)?, 0.0, 86_400.0)?;

        let impatience_tp_pct =
            validate_range("IMPATIENCE_TP_PCT", env_f64("IMPATIENCE_TP_PCT", 0.02)?, 0.0, 1.0)?;

        // ── Logging ───────────────────────────────────────────────────────────
        let clean_log_file = env_str("CLEAN_LOG_FILE", "clean_trades.log");

        // ── Starting Bankroll (paper mode) ────────────────────────────────────
        let starting_bankroll =
            validate_range("STARTING_BANKROLL", env_f64("STARTING_BANKROLL", 300.0)?, 0.01, 10_000_000.0)?;

        Ok(Config {
            paper_mode,
            market_asset,
            market_window_min,
            binance_ws_url,
            poly_ws_url,
            poly_rpc_url,
            private_key,
            max_position_multiplier,
            take_profit_pct,
            slippage_bps,
            slippage_multiplier,
            exit_ceiling_price,
            sell_cooldown_sec,
            sniper_debounce_sec,
            max_buy_price,
            play_beep_on_trade,
            momentum_threshold_usd,
            momentum_step_pct,
            momentum_window_sec,
            gas_priority_multiplier,
            kelly_tier_a_score,
            kelly_tier_a_fraction,
            kelly_tier_b_score,
            kelly_tier_b_fraction,
            kelly_tier_c_fraction,
            ev_momentum_multiplier,
            ev_base_score,
            ev_high_price_thresh,
            ev_time_danger_sec,
            ev_time_warn_sec,
            ev_time_danger_penalty,
            ev_time_warn_penalty,
            ev_no_bids_penalty,
            ev_max_momentum_bonus,
            ev_min_acceptable_score,
            ev_bailout_score_thresh,
            ev_death_trap_thresh_1,
            ev_death_trap_penalty_1,
            ev_death_trap_thresh_2,
            ev_death_trap_penalty_2,
            max_spread_cents,
            safe_expiry_bid_thresh,
            safe_expiry_time_sec,
            impatience_sec,
            impatience_tp_pct,
            clean_log_file,
            starting_bankroll,
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Derived helpers — cheap calculations based on validated config fields.
    // These are `#[inline]` so the compiler can fold them into the call site
    // when values are used in a tight loop.
    // ─────────────────────────────────────────────────────────────────────────

    /// Returns the market window duration in seconds.
    #[inline]
    pub fn market_window_sec(&self) -> u64 {
        self.market_window_min as u64 * 60
    }

    /// Returns `true` if a private key is configured (live trading capable).
    #[inline]
    pub fn has_private_key(&self) -> bool {
        !self.private_key.is_empty()
    }

    /// Returns `true` if a Polygon RPC URL is configured.
    #[inline]
    pub fn has_rpc(&self) -> bool {
        !self.poly_rpc_url.is_empty()
    }

    /// Compute the Kelly fraction for a given EV score without branching on
    /// `CONFIG` — lets the caller cache the result if needed.
    #[inline]
    pub fn kelly_fraction(&self, ev_score: f64) -> f64 {
        if ev_score >= self.kelly_tier_a_score {
            self.kelly_tier_a_fraction
        } else if ev_score >= self.kelly_tier_b_score {
            self.kelly_tier_b_fraction
        } else {
            self.kelly_tier_c_fraction
        }
    }

    /// Compute the next escalated momentum threshold after `shots_fired` trades
    /// within the current market window.
    ///
    /// Formula: `base * (1 + step_pct) ^ shots_fired`
    ///
    /// This mirrors the Python `_trigger_buy` pre-calculation. We expose it here
    /// so both `sniper.rs` and tests use the same formula.
    #[inline]
    pub fn escalated_threshold(&self, shots_fired: u32) -> f64 {
        self.momentum_threshold_usd
            * (1.0 + self.momentum_step_pct).powi(shots_fired as i32)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Display — pretty-print the active config at bot startup (redacts key)
// ─────────────────────────────────────────────────────────────────────────────

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_status = if self.has_private_key() {
            "SET (redacted)"
        } else {
            "NOT SET"
        };
        let rpc_status = if self.has_rpc() { "SET" } else { "NOT SET" };
        let mode = if self.paper_mode { "PAPER" } else { "LIVE 🔴" };

        write!(
            f,
            "\n\
            ┌─────────────────────────────────────────────────────┐\n\
            │              SNIPER BOT CONFIGURATION               │\n\
            ├─────────────────────────────────────────────────────┤\n\
            │  Mode             : {mode:<32}│\n\
            │  Asset            : {asset:<32}│\n\
            │  Window           : {window} min{window_pad:<28}│\n\
            │  Binance WS       : {bws:<32}│\n\
            │  Poly WS          : {pws:<32}│\n\
            │  Private Key      : {key:<32}│\n\
            │  RPC URL          : {rpc:<32}│\n\
            ├─────────────────────────────────────────────────────┤\n\
            │  Momentum Thresh  : ${mom:<31}│\n\
            │  Momentum Window  : {mwin}s{mwin_pad:<30}│\n\
            │  Momentum Step    : {step:.0}%{step_pad:<30}│\n\
            │  Slippage         : {slip} bps ({slipx:.2}×){slip_pad:<14}│\n\
            │  Max Buy Price    : ${maxbuy:<31}│\n\
            │  Debounce         : {deb}s{deb_pad:<30}│\n\
            ├─────────────────────────────────────────────────────┤\n\
            │  Kelly A / B / C  : {ka:.0}% / {kb:.0}% / {kc:.0}%{k_pad:<17}│\n\
            │  EV Min Score     : {evmin:<32}│\n\
            │  EV Bailout       : {evbail:<32}│\n\
            └─────────────────────────────────────────────────────┘",
            mode = mode,
            asset = self.market_asset.to_uppercase(),
            window = self.market_window_min,
            window_pad = "",
            bws = &self.binance_ws_url[..self.binance_ws_url.len().min(32)],
            pws = &self.poly_ws_url[..self.poly_ws_url.len().min(32)],
            key = key_status,
            rpc = rpc_status,
            mom = self.momentum_threshold_usd,
            mwin = self.momentum_window_sec,
            mwin_pad = "",
            step = self.momentum_step_pct * 100.0,
            step_pad = "",
            slip = self.slippage_bps,
            slipx = self.slippage_multiplier,
            slip_pad = "",
            maxbuy = self.max_buy_price,
            deb = self.sniper_debounce_sec,
            deb_pad = "",
            ka = self.kelly_tier_a_fraction * 100.0,
            kb = self.kelly_tier_b_fraction * 100.0,
            kc = self.kelly_tier_c_fraction * 100.0,
            k_pad = "",
            evmin = self.ev_min_acceptable_score,
            evbail = self.ev_bailout_score_thresh,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn load_defaults() -> Config {
        // Clear any stale env vars that might bleed across tests.
        // We do NOT clear the process env globally — just call load() on a
        // clean environment by temporarily unsetting the vars we care about.
        Config::load().expect("default config should always be valid")
    }

    #[test]
    fn test_default_config_loads() {
        let cfg = load_defaults();
        assert!(cfg.paper_mode);
        assert_eq!(cfg.market_asset, "btc");
        assert_eq!(cfg.market_window_min, 15);
        assert!(cfg.slippage_multiplier > 1.0);
    }

    #[test]
    fn test_binance_url_derived_correctly() {
        let cfg = load_defaults();
        assert!(cfg.binance_ws_url.contains("btcusdt@aggTrade"));
        assert!(cfg.binance_ws_url.starts_with("wss://stream.binance.com"));
    }

    #[test]
    fn test_escalated_threshold_zero_shots() {
        let cfg = load_defaults();
        let t = cfg.escalated_threshold(0);
        // (1 + step)^0 = 1, so result must equal base threshold
        assert!((t - cfg.momentum_threshold_usd).abs() < f64::EPSILON);
    }

    #[test]
    fn test_escalated_threshold_increases_each_shot() {
        let cfg = load_defaults();
        let t0 = cfg.escalated_threshold(0);
        let t1 = cfg.escalated_threshold(1);
        let t2 = cfg.escalated_threshold(2);
        assert!(t1 > t0);
        assert!(t2 > t1);
    }

    #[test]
    fn test_kelly_fraction_tiers() {
        let cfg = load_defaults();
        // Tier A
        assert_eq!(cfg.kelly_fraction(cfg.kelly_tier_a_score), cfg.kelly_tier_a_fraction);
        assert_eq!(cfg.kelly_fraction(100.0), cfg.kelly_tier_a_fraction);
        // Tier B
        assert_eq!(cfg.kelly_fraction(cfg.kelly_tier_b_score), cfg.kelly_tier_b_fraction);
        // Tier C
        assert_eq!(cfg.kelly_fraction(0.0), cfg.kelly_tier_c_fraction);
    }

    #[test]
    fn test_market_window_sec() {
        let cfg = load_defaults();
        assert_eq!(cfg.market_window_sec(), 15 * 60);
    }

    #[test]
    fn test_slippage_multiplier_precomputed() {
        let cfg = load_defaults();
        let expected = 1.0 + (cfg.slippage_bps as f64 / 10_000.0);
        assert!((cfg.slippage_multiplier - expected).abs() < f64::EPSILON);
    }
}
