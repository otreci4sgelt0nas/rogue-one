//! executor.rs — Polymarket CLOB order executor and global position manager.
//!
//! # Responsibilities
//!
//! 1. **Order execution**: [`ClobExecutor::execute_trade`] converts a
//!    [`TriggerSnapshot`] into a signed CLOB limit order (FAK — Fill-and-Kill),
//!    handles paper vs live mode, and returns a [`TradeOutcome`].
//!
//! 2. **Position tracking**: maintains a per-token VWAP cost basis, share count,
//!    and entry timestamp for every open position, used by the position manager.
//!
//! 3. **Position manager**: [`ClobExecutor::run_position_manager`] is a long-lived
//!    `tokio` task that wakes every 3 seconds and evaluates each open position
//!    against take-profit, impatience, and expiry-settlement logic.
//!
//! # Hot-path isolation
//!
//! `execute_trade` is **not** on the Binance tick hot path — it is called from
//! the [`crate::sniper::trigger_buy`] task that is spawned when a threshold
//! crossing is detected. Allocations, `String` formatting, and HTTP round-trips
//! are acceptable here.
//!
//! # Thread safety
//!
//! - `bankroll`: [`portable_atomic::AtomicF64`] — lock-free reads from any task.
//! - `positions`: [`parking_lot::Mutex<HashMap<...>>`] — taken only when a trade
//!   fires or the position manager wakes (both infrequent relative to tick rate).
//! - All other fields are either immutable after construction or behind a `Mutex`.
//!
//! # Kelly position sizing
//!
//! ```text
//! fraction    = kelly_fraction(ev_score)         // Tier A/B/C from config
//! target_spend = bankroll * fraction
//! sizing_price = best_ask  (raw, before slippage)
//! buy_size     = floor(target_spend / sizing_price)
//! ```
//!
//! The order is submitted at `limit_price` (= `best_ask * slippage_mult`, capped
//! at 0.99) to create a Marketable Limit Order that sweeps the book up to the
//! slippage ceiling — preventing "no orders found to match" rejections.
//!
//! # Binary Duality (already resolved)
//!
//! By the time `execute_trade` is called, the [`TriggerSnapshot`] already
//! contains `effective_ask` and `max_price` pre-computed via Binary Duality
//! in [`crate::streams::build_trigger_snapshot`]. The executor does not need
//! to re-run the duality logic.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use portable_atomic::AtomicF64;
use tracing::{debug, error, info, warn};

use crate::config::CONFIG;
use crate::errors::{ExecResult, ExecutorError};
use crate::live_trading::LiveSigner;
use crate::situation_room::{
    calculate_hold_ev, impatience_target_price, is_impatient, is_safe_to_hold_to_expiry,
};
use crate::sniper::TradeOutcome;
use crate::state::{load_price, unix_now_secs, Direction, SharedState};
use crate::state::TriggerSnapshot;

// ─────────────────────────────────────────────────────────────────────────────
// Position record — tracks one open token position
// ─────────────────────────────────────────────────────────────────────────────

/// A single open position for one Polymarket CLOB token.
///
/// All monetary fields are in USD. Shares are integer CLOB shares
/// (1 share = $1 face value at settlement).
#[derive(Debug, Clone)]
pub struct Position {
    /// CLOB token ID (the key in [`ClobExecutor::positions`]).
    pub token_id: String,

    /// Cumulative USD spent on this position across all fill legs.
    pub total_spent: f64,

    /// Total shares held.
    pub total_shares: u64,

    /// Volume-Weighted Average Price of entry.
    ///
    /// `vwap = total_spent / total_shares`
    pub cost_basis: f64,

    /// Wall-clock instant when the first fill for this position was recorded.
    pub entry_time: Instant,

    /// Unix timestamp (seconds) of entry — for impatience timer calculations.
    pub entry_unix_secs: f64,

    /// Wall-clock instant of the last successful sell on this token.
    /// Used to enforce `CONFIG.sell_cooldown_sec`.
    pub last_sell_time: Option<Instant>,

    /// The direction of the original trade (UP or DOWN).
    pub direction: Direction,

    /// Market slug at time of entry (for logging and redemption).
    pub market_slug: String,

    /// UMA condition ID for this market window (for auto-redemption).
    pub condition_id: String,

    /// Whether this position's market is a neg-risk market (affects EIP-712
    /// exchange contract address used for signing sell orders).
    pub neg_risk: bool,
}

impl Position {
    /// Construct a new position from a first fill.
    pub fn new(
        token_id:    String,
        fill_price:  f64,
        fill_size:   u64,
        direction:   Direction,
        market_slug: String,
        condition_id: String,
        neg_risk:    bool,
    ) -> Self {
        let total_spent = fill_price * fill_size as f64;
        Self {
            token_id,
            total_spent,
            total_shares:    fill_size,
            cost_basis:      fill_price,
            entry_time:      Instant::now(),
            entry_unix_secs: unix_now_secs(),
            last_sell_time:  None,
            direction,
            market_slug,
            condition_id,
            neg_risk,
        }
    }

    /// Update the position with an additional fill (averaging down/up).
    ///
    /// Recomputes the VWAP cost basis:
    /// `new_vwap = (old_spent + new_spent) / (old_shares + new_shares)`
    pub fn add_fill(&mut self, fill_price: f64, fill_size: u64) {
        self.total_spent  += fill_price * fill_size as f64;
        self.total_shares += fill_size;
        if self.total_shares > 0 {
            self.cost_basis = self.total_spent / self.total_shares as f64;
        }
    }

    /// Returns `true` if the sell cooldown has elapsed since the last sell.
    pub fn sell_cooldown_elapsed(&self) -> bool {
        match self.last_sell_time {
            None       => true,
            Some(last) => last.elapsed().as_secs_f64() >= CONFIG.sell_cooldown_sec,
        }
    }

    /// Returns the current unrealised P&L given a market price.
    #[inline]
    pub fn unrealised_pnl(&self, current_price: f64) -> f64 {
        (current_price - self.cost_basis) * self.total_shares as f64
    }

    /// Returns the take-profit target price based on the entry VWAP.
    ///
    /// `tp = cost_basis * (1 + take_profit_pct)`, capped at `EXIT_CEILING_PRICE`.
    #[inline]
    pub fn take_profit_price(&self) -> f64 {
        (self.cost_basis * (1.0 + CONFIG.take_profit_pct)).min(CONFIG.exit_ceiling_price)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Paper trading ledger
// ─────────────────────────────────────────────────────────────────────────────

/// Simulated token balances for paper trading mode.
///
/// In live mode this is empty — balances are read from the on-chain ERC-1155
/// contract via Web3 RPC.
#[derive(Debug, Default)]
pub struct PaperLedger {
    /// Simulated share balances per token ID.
    pub balances: HashMap<String, f64>,

    /// Cumulative realised P&L for this session.
    pub session_pnl: f64,

    /// P&L for the current market window.
    pub window_pnl: f64,
}

impl PaperLedger {
    pub fn credit_buy(&mut self, token_id: &str, shares: u64) {
        *self.balances.entry(token_id.to_string()).or_insert(0.0) += shares as f64;
    }

    pub fn debit_sell(&mut self, token_id: &str, shares: u64) {
        let bal = self.balances.entry(token_id.to_string()).or_insert(0.0);
        *bal = (*bal - shares as f64).max(0.0);
    }

    pub fn balance(&self, token_id: &str) -> f64 {
        self.balances.get(token_id).copied().unwrap_or(0.0)
    }

    pub fn record_pnl(&mut self, pnl: f64) {
        self.session_pnl += pnl;
        self.window_pnl  += pnl;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP order request / response shapes (CLOB REST API)
// ─────────────────────────────────────────────────────────────────────────────

/// The JSON body sent to the Polymarket CLOB `/order` endpoint.
///
/// Field names must match the CLOB API specification exactly.
/// `serde(rename_all = "camelCase")` handles the snake_case → camelCase mapping.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ClobOrderRequest {
    /// CLOB token ID of the asset being bought/sold.
    token_id: String,

    /// Limit price in USD (e.g. `0.72`). Range: [0.01, 0.99].
    price: f64,

    /// Number of shares (integer).
    size: u64,

    /// `"BUY"` or `"SELL"`.
    side: &'static str,

    /// Order type. `"FAK"` = Fill-and-Kill (marketable limit order).
    order_type: &'static str,

    /// Base64-encoded ECDSA signature of the EIP-712 order digest.
    signature: String,

    /// Signer's Ethereum address (checksummed).
    signer: String,
}

/// The JSON response from the CLOB `/order` endpoint.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClobOrderResponse {
    success: bool,
    order_id: Option<String>,
    size: Option<f64>,
    price: Option<f64>,
    error_msg: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ClobExecutor
// ─────────────────────────────────────────────────────────────────────────────

/// Polymarket CLOB order executor and global position manager.
///
/// Constructed once in [`crate::sniper::SniperBrain::new`] and wrapped in
/// `Arc<ClobExecutor>` so both the trigger task and the position manager can
/// hold a reference without lifetime gymnastics.
///
/// # Paper mode
///
/// When `CONFIG.paper_mode == true`, all orders are simulated in-memory.
/// No HTTP calls are made to the CLOB. The paper ledger is updated as if
/// fills were real, and P&L is tracked for the session.
///
/// # Live mode
///
/// Orders are sent to `https://clob.polymarket.com/order` as signed FAK limit
/// orders. The private key is used to derive L2 API credentials (EIP-712
/// signing) on construction.
#[derive(Debug)]
pub struct ClobExecutor {
    // ── Shared state ──────────────────────────────────────────────────────────
    /// Access to the market info and orderbook (for position manager reads).
    state: Arc<SharedState>,

    // ── HTTP client (reused across all order calls) ───────────────────────────
    /// Persistent `reqwest` client with connection keep-alive to the CLOB.
    pub http: reqwest::Client,

    // ── Bankroll ──────────────────────────────────────────────────────────────
    /// Current available USD balance.
    ///
    /// - Paper mode: initialised from `CONFIG.starting_bankroll`, updated locally.
    /// - Live mode:  initialised from on-chain USDC balance via Web3 RPC, then
    ///   reconciled periodically by the position manager.
    ///
    /// `AtomicF64` allows the position manager and the buy executor to read/write
    /// without a lock — both paths are single-threaded in practice (the position
    /// manager runs on its own task; buy executions are serialised by `is_armed`),
    /// but `AtomicF64` makes the invariant explicit and eliminates any UB risk.
    pub bankroll: AtomicF64,

    // ── Open positions ────────────────────────────────────────────────────────
    /// Map of `token_id → Position` for all currently open positions.
    ///
    /// Protected by `parking_lot::Mutex` (never called on the hot tick path).
    positions: Mutex<HashMap<String, Position>>,

    // ── Paper trading ledger ─────────────────────────────────────────────────
    /// In-memory simulated balance and P&L tracking for paper mode.
    paper_ledger: Mutex<PaperLedger>,

    // ── Authentication ────────────────────────────────────────────────────────
    /// Whether L2 API credentials have been successfully derived.
    pub is_authenticated: bool,

    /// Ethereum address derived from `CONFIG.private_key` (checksummed hex).
    pub wallet_address: Option<String>,

    // ── Session metadata ─────────────────────────────────────────────────────
    /// CSV filename for this trading session (paper mode only).
    ///
    /// Format: `paper_trades_{YYYYMMDD_HHMMSS}.csv`
    pub csv_filename: String,

    /// Expiry timestamp of the last completed window (for per-window P&L reset).
    pub last_summary_expiry: Mutex<Option<u64>>,

    /// Live trading signer — owns the parsed secp256k1 key and wallet address.
    /// `None` in paper mode or when PRIVATE_KEY is absent/invalid.
    pub signer: Option<Arc<LiveSigner>>,

    /// Polymarket L2 API credentials (api_key, api_secret, api_passphrase).
    /// Derived at startup from the private key via `/auth/derive-api-key`.
    /// `None` until `set_api_credentials` is called from main.
    pub api_creds: Mutex<Option<crate::live_trading::ApiCredentials>>,
}

impl ClobExecutor {
    // ─────────────────────────────────────────────────────────────────────────
    // Construction
    // ─────────────────────────────────────────────────────────────────────────

    /// Construct a new `ClobExecutor`.
    ///
    /// - Builds the shared `reqwest::Client` with `rustls` TLS and HTTP/2.
    /// - Derives L2 API credentials from the private key (if set).
    /// - Initialises the bankroll from config (paper) or defers to RPC (live).
    pub fn new(state: Arc<SharedState>) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .tcp_keepalive(Duration::from_secs(30))
            .http2_keep_alive_interval(Duration::from_secs(20))
            .gzip(true)
            .user_agent("sniper-bot/0.1")
            .build()
            .expect("Failed to build reqwest client for ClobExecutor");

        // ── Session CSV filename ───────────────────────────────────────────────
        let session_time = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let csv_filename = format!("paper_trades_{}.csv", session_time);

        // ── Initial bankroll ──────────────────────────────────────────────────
        // In paper mode we use the configured starting bankroll.
        // In live mode, bankroll is 0.0 here and will be reconciled from
        // on-chain USDC balance by `run_position_manager` on first iteration.
        let initial_bankroll = if CONFIG.paper_mode {
            info!(
                bankroll = CONFIG.starting_bankroll,
                "📄 PAPER MODE: Initialised simulated bankroll."
            );
            CONFIG.starting_bankroll
        } else {
            // Will be fetched on-chain during position manager startup.
            info!("🔴 LIVE MODE: Bankroll will be fetched from on-chain USDC balance.");
            0.0
        };

        // ── L2 credential derivation ─────────────────────────────────────────
        let signer_result = if CONFIG.has_private_key() {
            match LiveSigner::from_hex_key(&CONFIG.private_key) {
                Ok(s) => {
                    info!(address = %s.wallet_address, "✅ LiveSigner constructed — live orders enabled.");
                    Some(Arc::new(s))
                }
                Err(e) => {
                    warn!("⚠️  LiveSigner failed: {e}. Live orders disabled.");
                    None
                }
            }
        } else {
            warn!("PRIVATE_KEY not set — live order execution is disabled.");
            None
        };

        let is_authenticated = signer_result.is_some();
        let wallet_address   = signer_result.as_ref().map(|s| s.wallet_address.clone());

        Arc::new(Self {
            state,
            http,
            bankroll:          AtomicF64::new(initial_bankroll),
            positions:         Mutex::new(HashMap::new()),
            paper_ledger:      Mutex::new(PaperLedger::default()),
            is_authenticated,
            wallet_address,
            csv_filename,
            last_summary_expiry: Mutex::new(None),
            signer:    signer_result,
            api_creds: Mutex::new(None),
        })
    }

    /// Store L2 API credentials derived at startup.
    pub fn set_api_credentials(&self, creds: crate::live_trading::ApiCredentials) {
        *self.api_creds.lock() = Some(creds);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bankroll helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Read the current bankroll.
    #[inline(always)]
    pub fn bankroll(&self) -> f64 {
        self.bankroll.load(Ordering::Acquire)
    }

    /// Deduct an amount from the bankroll atomically (best-effort CAS loop).
    ///
    /// Returns `true` if the deduction succeeded (sufficient funds).
    /// Returns `false` if the bankroll would go negative.
    fn deduct_bankroll(&self, amount: f64) -> bool {
        loop {
            let current = self.bankroll.load(Ordering::Acquire);
            if current < amount {
                return false;
            }
            let new_val = current - amount;
            // Use a CAS to avoid a concurrent deduction racing us.
            // portable_atomic::AtomicF64 doesn't have compare_exchange_float,
            // so we approximate with a bit-level CAS via u64 reinterpretation.
            // In practice, execute_trade is serialised by `is_armed`, so this
            // is almost never contended.
            match self.bankroll.compare_exchange(
                current,
                new_val,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_)  => return true,
                Err(_) => continue, // Retry if another task raced us.
            }
        }
    }

    /// Credit the bankroll (used on paper sells or reconciliation).
    fn credit_bankroll(&self, amount: f64) {
        // fetch_add doesn't exist on AtomicF64 directly via portable-atomic;
        // we use a CAS loop for correctness.
        loop {
            let current = self.bankroll.load(Ordering::Acquire);
            let new_val = current + amount;
            match self.bankroll.compare_exchange(
                current,
                new_val,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_)  => return,
                Err(_) => continue,
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // execute_trade — the primary execution entry point
    // ─────────────────────────────────────────────────────────────────────────

    /// Execute a buy order from a [`TriggerSnapshot`].
    ///
    /// # Flow
    ///
    /// 1. Gate: authentication check (live mode only).
    /// 2. Clamp `max_price` to the valid CLOB range `[0.01, 0.99]`.
    /// 3. Compute Kelly position size (`target_spend / sizing_price`).
    /// 4. Validate: minimum order value ($1), dust threshold, bankroll check.
    /// 5. Log wire latency and spread diagnostic.
    /// 6. Branch: paper execution or live CLOB HTTP order.
    /// 7. On fill: update `positions`, deduct `bankroll`, log CSV entry.
    ///
    /// # Returns
    /// - `Ok(TradeOutcome)` on a successful fill (paper or live).
    /// - `Err(ExecutorError)` on any validation failure or network error.
    ///   The caller (`trigger_buy`) always re-arms after an `Err`.
    pub async fn execute_trade(&self, snap: &TriggerSnapshot) -> ExecResult<TradeOutcome> {
        // ── Gate: authentication (live mode only) ──────────────────────────────
        if !CONFIG.paper_mode && !self.is_authenticated {
            return Err(ExecutorError::NotAuthenticated);
        }

        // ── Clamp to valid CLOB price range ───────────────────────────────────
        let buy_price = {
            let p = snap.max_price.max(0.01).min(0.99);
            // Round to 2 decimal places to match CLOB tick size.
            (p * 100.0).round() / 100.0
        };

        if buy_price <= 0.01 {
            return Err(ExecutorError::InvalidPrice { price: buy_price });
        }

        // ── Wire latency diagnostic ───────────────────────────────────────────
        let wire_ms = snap.trigger_instant.elapsed().as_secs_f64() * 1000.0;

        // ── Kelly position sizing ─────────────────────────────────────────────
        // ev_score is a placeholder (100.0) since the EV floor was already
        // enforced by SituationRoom — if we reached this point, the trade passed.
        let ev_score     = 100.0_f64;
        let fraction     = CONFIG.kelly_fraction(ev_score);
        let bankroll_now = self.bankroll();
        let target_spend = bankroll_now * fraction;

        // Size at `best_ask` (raw, before slippage) to maximise share count.
        // The order is submitted at `buy_price` (slippage cap) creating a
        // Marketable Limit Order that sweeps the book up to our ceiling.
        let sizing_price = snap.effective_ask.max(0.001);
        let buy_size     = (target_spend / sizing_price) as u64;

        // ── Bankroll gate ──────────────────────────────────────────────────────
        if buy_size < 1 {
            warn!(
                bankroll  = bankroll_now,
                price     = sizing_price,
                fraction  = fraction,
                "💀 Bankroll too low to buy 1 share. Aborting."
            );
            return Err(ExecutorError::InsufficientBankroll {
                bankroll: bankroll_now,
                price:    sizing_price,
            });
        }

        let order_value = buy_price * buy_size as f64;

        // ── Minimum order value ($1) ───────────────────────────────────────────
        if order_value < 1.0 {
            warn!(value = order_value, "🚫 Order value below $1.00 minimum.");
            return Err(ExecutorError::BelowMinimum { value: order_value });
        }

        // ── Bankroll sufficiency ───────────────────────────────────────────────
        if order_value > bankroll_now {
            warn!(
                needed  = order_value,
                have    = bankroll_now,
                "🚫 Insufficient bankroll for order."
            );
            return Err(ExecutorError::InsufficientBankroll {
                bankroll: bankroll_now,
                price:    buy_price,
            });
        }

        // ── Dust gate (live mode only) ─────────────────────────────────────────
        if !CONFIG.paper_mode && buy_size < 5 {
            warn!(
                size = buy_size,
                "🚫 Order too small (dust). Aborting to save throughput."
            );
            return Err(ExecutorError::DustOrder {
                size:     buy_size,
                min_size: 5,
            });
        }

        // ── Pre-fire diagnostic log ───────────────────────────────────────────
        let spread_str = match snap.spread {
            Some(s) => format!("${:.4}", s),
            None    => "N/A".to_string(),
        };
        info!(
            wire_ms    = wire_ms,
            spread     = %spread_str,
            ask_at_trigger = snap.effective_ask,
            order_price    = buy_price,
            order_size     = buy_size,
            order_value    = order_value,
            direction      = %snap.direction,
            token          = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
            "📡 Execution Latency & Spread diagnostic."
        );

        // ── Execution branch ──────────────────────────────────────────────────
        if CONFIG.paper_mode {
            self.execute_paper(snap, buy_price, buy_size, order_value).await
        } else {
            self.execute_live(snap, buy_price, buy_size, order_value, wire_ms, &spread_str).await
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Paper execution
    // ─────────────────────────────────────────────────────────────────────────

    async fn execute_paper(
        &self,
        snap:        &TriggerSnapshot,
        buy_price:   f64,
        buy_size:    u64,
        order_value: f64,
    ) -> ExecResult<TradeOutcome> {
        // Deduct from bankroll atomically.
        if !self.deduct_bankroll(order_value) {
            return Err(ExecutorError::InsufficientBankroll {
                bankroll: self.bankroll(),
                price:    buy_price,
            });
        }

        // Update paper ledger balances.
        {
            let mut ledger = self.paper_ledger.lock();
            ledger.credit_buy(&snap.token_id, buy_size);
        }

        // Upsert position record.
        self.upsert_position(snap, buy_price, buy_size);

        let wire_ms = snap.trigger_instant.elapsed().as_secs_f64() * 1000.0;
        info!(
            shares   = buy_size,
            price    = buy_price,
            wire_ms  = wire_ms,
            bankroll = self.bankroll(),
            token    = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
            "📄 PAPER BUY SECURED."
        );

        // Append to CSV (non-blocking).
        self.append_csv_entry_async("BUY", &snap.token_id, buy_size as f64, buy_price, 0.0, 0.0);

        Ok(TradeOutcome::filled(buy_price, buy_size, None))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Live execution
    // ─────────────────────────────────────────────────────────────────────────

    async fn execute_live(
        &self,
        snap:        &TriggerSnapshot,
        buy_price:   f64,
        buy_size:    u64,
        _order_value: f64,
        wire_ms:     f64,
        spread_str:  &str,
    ) -> ExecResult<TradeOutcome> {
        let signer = self.signer.as_ref().ok_or(ExecutorError::NotAuthenticated)?;
        let creds  = self.api_creds.lock();
        let creds  = creds.as_ref().ok_or(ExecutorError::NotAuthenticated)?;
        let order_value = buy_price * buy_size as f64;

        warn!(
            size      = buy_size,
            price     = buy_price,
            direction = %snap.direction,
            token     = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
            wire_ms   = wire_ms,
            spread    = %spread_str,
            "🚨 FIRING LIVE ORDER."
        );

        let (fill_price, fill_size, _order_id) =
            crate::live_trading::execute_live_buy(
                &self.http,
                signer,
                creds,
                &snap.token_id,
                buy_price,
                buy_size,
                order_value,
                snap.neg_risk,
            )
            .await
            .map_err(|e| ExecutorError::OrderRejected {
                token_id:  snap.token_id.clone(),
                error_msg: e,
            })?;

        if !self.deduct_bankroll(order_value) {
            return Err(ExecutorError::InsufficientBankroll {
                bankroll: self.bankroll(),
                price:    buy_price,
            });
        }

        self.upsert_position(snap, fill_price, fill_size);
        self.append_csv_entry_async("BUY", &snap.token_id, fill_size as f64, fill_price, 0.0, 0.0);

        Ok(TradeOutcome::filled(fill_price, fill_size, None))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Position tracking helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Insert a new position or add a fill to an existing one (VWAP averaging).
    fn upsert_position(&self, snap: &TriggerSnapshot, fill_price: f64, fill_size: u64) {
        let mut positions = self.positions.lock();
        match positions.get_mut(&snap.token_id) {
            Some(pos) => {
                pos.add_fill(fill_price, fill_size);
                debug!(
                    token      = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
                    new_vwap   = pos.cost_basis,
                    new_shares = pos.total_shares,
                    "Position averaged in."
                );
            }
            None => {
                // Load condition_id from the current market info.
                let condition_id = self
                    .state
                    .market
                    .load()
                    .as_ref()
                    .map(|m| m.condition_id.clone())
                    .unwrap_or_default();

                let pos = Position::new(
                    snap.token_id.clone(),
                    fill_price,
                    fill_size,
                    snap.direction,
                    snap.market_slug.clone(),
                    condition_id,
                    snap.neg_risk,
                );
                debug!(
                    token    = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
                    cost     = fill_price,
                    shares   = fill_size,
                    "New position opened."
                );
                positions.insert(snap.token_id.clone(), pos);
            }
        }
    }

    /// Get the current on-chain (or paper) token balance for a given token.
    ///
    /// In paper mode, reads from the in-memory ledger.
    /// In live mode, queries the ERC-1155 contract via Web3 RPC.
    ///
    /// Returns `0.0` if the balance cannot be determined.
    async fn get_token_balance(&self, token_id: &str) -> f64 {
        if CONFIG.paper_mode {
            return self.paper_ledger.lock().balance(token_id);
        }

        // Live mode: query the CTF ERC-1155 contract via RPC.
        let signer = match self.signer.as_ref() {
            Some(s) => s,
            None    => return 0.0,
        };

        match crate::live_trading::get_ctf_balance(
            &self.http,
            &CONFIG.poly_rpc_url,
            &signer.wallet_address,
            token_id,
        )
        .await
        {
            Ok(bal) => bal,
            Err(e)  => {
                warn!(token = %token_id, error = %e, "CTF balance fetch failed.");
                0.0
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CSV trade logging
    // ─────────────────────────────────────────────────────────────────────────

    /// Append a trade record to the session CSV file.
    ///
    /// This is a fire-and-forget spawn — CSV I/O never blocks the executor.
    fn append_csv_entry_async(
        &self,
        action:      &'static str,
        token_id:    &str,
        shares:      f64,
        entry_price: f64,
        exit_price:  f64,
        trade_pnl:   f64,
    ) {
        // Clone strings for the spawned task.
        let filename    = self.csv_filename.clone();
        let token_short = token_id[token_id.len().saturating_sub(6)..].to_string();
        let session_pnl = self.paper_ledger.lock().session_pnl;

        tokio::spawn(async move {
            if let Err(e) = write_csv_row(
                &filename,
                action,
                &token_short,
                shares,
                entry_price,
                exit_price,
                trade_pnl,
                session_pnl,
            )
            .await
            {
                warn!(error = %e, "Failed to write CSV trade log row.");
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // run_position_manager — the global position manager background loop
    // ─────────────────────────────────────────────────────────────────────────

    /// Long-running background task that evaluates all open positions every 3 s.
    ///
    /// # Logic per position (mirrors Python `start_position_manager`)
    ///
    /// For each open position:
    ///
    /// 1. **Expiry check**: if the market has expired and we hold the winning
    ///    leg, trigger auto-redemption via `scripts/redeem.py`.
    ///
    /// 2. **Safe-to-expiry**: if bid ≥ `SAFE_EXPIRY_BID_THRESH` and there's
    ///    enough time left, skip the position (let it resolve naturally).
    ///
    /// 3. **Sell cooldown**: skip if the sell cooldown hasn't elapsed.
    ///
    /// 4. **Hold EV bailout**: if hold EV < `EV_BAILOUT_SCORE_THRESH`, sell
    ///    immediately to cut losses.
    ///
    /// 5. **Impatience TP**: if the position has been open for >
    ///    `IMPATIENCE_SEC` and bid has risen by `IMPATIENCE_TP_PCT`, sell.
    ///
    /// 6. **Primary TP**: if bid ≥ `take_profit_price()`, sell.
    ///
    /// # Bankroll reconciliation
    ///
    /// Every 60 seconds in live mode, the bankroll is reconciled from the
    /// on-chain USDC.e balance. This catches any fills or transfers that
    /// happened outside the bot's tracking.
    pub async fn run_position_manager(self: Arc<Self>) {
        info!("🏦 Global Position Manager started.");

        let poll_interval     = Duration::from_secs(3);
        let reconcile_interval = Duration::from_secs(60);
        let mut last_reconcile = Instant::now();

        loop {
            tokio::time::sleep(poll_interval).await;

            // ── Skip during rollover ──────────────────────────────────────────
            if self.state.is_rolling_over() {
                debug!("[PositionManager] Rollover in progress — skipping iteration.");
                continue;
            }

            // ── Snapshot current time and market state ────────────────────────
            let now_secs  = unix_now_secs();
            let expiry_ts = self.state.market_expiry_secs();
            let time_left = (expiry_ts - now_secs).max(0.0);

            // ── Bankroll reconciliation (live mode, every 60s) ────────────────
            if !CONFIG.paper_mode && last_reconcile.elapsed() >= reconcile_interval {
                self.reconcile_bankroll_live().await;
                last_reconcile = Instant::now();
            }

            // ── Per-position evaluation ───────────────────────────────────────
            // Snapshot the token IDs to process to avoid holding the lock.
            let token_ids: Vec<String> = {
                let positions = self.positions.lock();
                positions.keys().cloned().collect()
            };

            for token_id in token_ids {
                self.evaluate_position(&token_id, now_secs, time_left, expiry_ts).await;
            }
        }
    }

    /// Evaluate a single position against all exit conditions.
    async fn evaluate_position(
        &self,
        token_id:  &str,
        now_secs:  f64,
        time_left: f64,
        expiry_ts: f64,
    ) {
        // ── Read position data (short lock scope) ─────────────────────────────
        let (cost_basis, total_shares, entry_unix, direction, market_slug, condition_id) = {
            let positions = self.positions.lock();
            match positions.get(token_id) {
                Some(pos) => (
                    pos.cost_basis,
                    pos.total_shares,
                    pos.entry_unix_secs,
                    pos.direction,
                    pos.market_slug.clone(),
                    pos.condition_id.clone(),
                ),
                None => return, // Position was removed by a concurrent sell.
            }
        };

        if total_shares == 0 {
            // Stale zero-share entry — clean up.
            self.positions.lock().remove(token_id);
            return;
        }

        // ── Read current best bid from the orderbook atomics ──────────────────
        let best_bid = match direction {
            Direction::Up   => load_price(&self.state.book.best_bid_up,   Ordering::Acquire),
            Direction::Down => load_price(&self.state.book.best_bid_down, Ordering::Acquire),
        };

        let bid = match best_bid {
            Some(b) if b > 0.0 => b,
            _ => {
                debug!(
                    token     = %&token_id[token_id.len().saturating_sub(6)..],
                    direction = %direction,
                    "[PositionManager] No bid data — skipping position."
                );
                return;
            }
        };

        // ── 1. Market expiry — trigger auto-redemption ────────────────────────
        if expiry_ts > 0.0 && now_secs >= expiry_ts {
            info!(
                token      = %&token_id[token_id.len().saturating_sub(6)..],
                direction  = %direction,
                market     = %market_slug,
                "⏰ Market expired. Initiating auto-redemption for condition {}.",
                condition_id
            );
            self.trigger_auto_redeem(&condition_id).await;
            // Remove position after redemption trigger.
            self.positions.lock().remove(token_id);
            return;
        }

        // ── 2. Safe-to-expiry hold ────────────────────────────────────────────
        if is_safe_to_hold_to_expiry(bid, time_left) {
            debug!(
                token     = %&token_id[token_id.len().saturating_sub(6)..],
                bid       = bid,
                time_left = time_left,
                "[PositionManager] Position is safe — holding to expiry."
            );
            return;
        }

        // ── 3. Sell cooldown gate ─────────────────────────────────────────────
        let cooldown_elapsed = {
            let positions = self.positions.lock();
            positions
                .get(token_id)
                .map(|p| p.sell_cooldown_elapsed())
                .unwrap_or(false)
        };
        if !cooldown_elapsed {
            return;
        }

        // ── 4. Hold EV bailout ────────────────────────────────────────────────
        let hold_ev = calculate_hold_ev(bid, cost_basis, time_left);
        if hold_ev < CONFIG.ev_bailout_score_thresh {
            warn!(
                token     = %&token_id[token_id.len().saturating_sub(6)..],
                hold_ev   = hold_ev,
                threshold = CONFIG.ev_bailout_score_thresh,
                bid       = bid,
                cost      = cost_basis,
                "📉 Hold EV below bailout threshold — force exiting position."
            );
            self.execute_sell(token_id, bid, total_shares, "BAILOUT", now_secs).await;
            return;
        }

        // ── 5. Impatience TP (micro-bounce escape) ────────────────────────────
        if is_impatient(entry_unix, now_secs) {
            let impatience_tp = impatience_target_price(cost_basis);
            if bid >= impatience_tp {
                info!(
                    token         = %&token_id[token_id.len().saturating_sub(6)..],
                    bid           = bid,
                    impatience_tp = impatience_tp,
                    cost          = cost_basis,
                    "[PositionManager] ⏰ Impatience TP hit — selling micro-bounce."
                );
                self.execute_sell(token_id, bid, total_shares, "IMPATIENCE_TP", now_secs).await;
                return;
            }
        }

        // ── 6. Primary take-profit ────────────────────────────────────────────
        let tp_price = {
            let positions = self.positions.lock();
            positions.get(token_id).map(|p| p.take_profit_price())
        };

        if let Some(tp) = tp_price {
            if bid >= tp {
                info!(
                    token    = %&token_id[token_id.len().saturating_sub(6)..],
                    bid      = bid,
                    tp_price = tp,
                    cost     = cost_basis,
                    pnl      = (bid - cost_basis) * total_shares as f64,
                    "[PositionManager] 🎯 Take-profit target reached — selling."
                );
                self.execute_sell(token_id, bid, total_shares, "TAKE_PROFIT", now_secs).await;
            }
        }
    }

    /// Execute a sell order for a position.
    ///
    /// In paper mode: updates the ledger and bankroll immediately.
    /// In live mode: POSTs a SELL FAK order to the CLOB.
    ///
    /// Always removes the position record on success.
    async fn execute_sell(
        &self,
        token_id:  &str,
        sell_price: f64,
        shares:     u64,
        reason:     &'static str,
        _now_secs:  f64,
    ) {
        // Read cost basis and neg_risk before removing (needed for P&L and signing).
        let (cost_basis, neg_risk) = {
            let positions = self.positions.lock();
            positions.get(token_id)
                .map(|p| (p.cost_basis, p.neg_risk))
                .unwrap_or((0.0, true)) // default neg_risk=true for btc/eth markets
        };

        let gross_proceeds = sell_price * shares as f64;
        let pnl            = (sell_price - cost_basis) * shares as f64;

        if CONFIG.paper_mode {
            // ── Paper sell ────────────────────────────────────────────────────
            {
                let mut ledger = self.paper_ledger.lock();
                ledger.debit_sell(token_id, shares);
                ledger.record_pnl(pnl);
            }
            self.credit_bankroll(gross_proceeds);

            let token_short = &token_id[token_id.len().saturating_sub(6)..];
            if pnl >= 0.0 {
                info!(
                    token   = %token_short,
                    shares  = shares,
                    price   = sell_price,
                    cost    = cost_basis,
                    pnl     = pnl,
                    reason  = reason,
                    bankroll = self.bankroll(),
                    "💚 PAPER SELL — profit."
                );
            } else {
                warn!(
                    token   = %token_short,
                    shares  = shares,
                    price   = sell_price,
                    cost    = cost_basis,
                    pnl     = pnl,
                    reason  = reason,
                    bankroll = self.bankroll(),
                    "🔴 PAPER SELL — loss."
                );
            }

            self.append_csv_entry_async(
                "SELL",
                token_id,
                shares as f64,
                cost_basis,
                sell_price,
                pnl,
            );
        } else {
            // ── Live sell ──────────────────────────────────────────────────
            let signer = match self.signer.as_ref() {
                Some(s) => s,
                None => {
                    warn!(
                        token  = %&token_id[token_id.len().saturating_sub(6)..],
                        reason = reason,
                        "Live sell skipped — no signer."
                    );
                    return;
                }
            };
            let creds_guard = self.api_creds.lock();
            let creds = match creds_guard.as_ref() {
                Some(c) => c,
                None => {
                    warn!(token = %&token_id[token_id.len().saturating_sub(6)..], "Live sell skipped — no API credentials.");
                    return;
                }
            };

            match crate::live_trading::execute_live_sell(
                &self.http,
                signer,
                creds,
                token_id,
                sell_price,
                shares,
                neg_risk,
            )
            .await
            {
                Ok((proceeds, _order_id)) => {
                    self.credit_bankroll(proceeds);
                    if pnl >= 0.0 {
                        info!(
                            token    = %&token_id[token_id.len().saturating_sub(6)..],
                            shares, price = sell_price, cost = cost_basis, pnl, reason,
                            bankroll = self.bankroll(),
                            "💚 LIVE SELL — profit."
                        );
                    } else {
                        warn!(
                            token    = %&token_id[token_id.len().saturating_sub(6)..],
                            shares, price = sell_price, cost = cost_basis, pnl, reason,
                            bankroll = self.bankroll(),
                            "🔴 LIVE SELL — loss."
                        );
                    }
                    self.append_csv_entry_async(
                        "SELL", token_id, shares as f64, cost_basis, sell_price, pnl,
                    );
                }
                Err(e) => {
                    error!(
                        token  = %&token_id[token_id.len().saturating_sub(6)..],
                        reason = reason,
                        error  = %e,
                        "❌ Live sell failed — position retained for retry."
                    );
                    return; // Don't remove position — retry on next manager tick.
                }
            }
        }

        // ── Remove the position record ─────────────────────────────────────────
        self.positions.lock().remove(token_id);
    }

    /// Trigger the auto-redemption for an expired market.
    ///
    /// Calls the CTF `redeemPositions` function directly via a signed
    /// EIP-1559 transaction — no Python subprocess required.
    async fn trigger_auto_redeem(&self, condition_id: &str) {
        if condition_id.is_empty() {
            warn!("Auto-redeem: no condition ID — skipping.");
            return;
        }

        let signer = match self.signer.as_ref() {
            Some(s) => s,
            None => {
                warn!("Auto-redeem: no signer — cannot redeem on-chain. Redeem manually via the Polymarket UI.");
                return;
            }
        };

        crate::live_trading::trigger_auto_redeem_native(
            &self.http,
            &CONFIG.poly_rpc_url,
            signer,
            condition_id,
        )
        .await;
    }

    /// Reconcile the bankroll from the on-chain USDC.e balance (live mode only).
    async fn reconcile_bankroll_live(&self) {
        let signer = match self.signer.as_ref() {
            Some(s) => s,
            None    => return,
        };

        if CONFIG.poly_rpc_url.is_empty() {
            debug!("Bankroll reconciliation skipped — POLY_RPC_URL not set.");
            return;
        }

        match crate::live_trading::get_usdc_balance(
            &self.http,
            &CONFIG.poly_rpc_url,
            &signer.wallet_address,
        )
        .await
        {
            Ok(usdc) => {
                let prev = self.bankroll();
                if (usdc - prev).abs() > 0.01 {
                    info!(prev, usdc, "💰 Bankroll reconciled from on-chain USDC.");
                    self.bankroll.store(usdc, Ordering::Release);
                }
            }
            Err(e) => {
                warn!(error = %e, "Bankroll reconciliation failed — retaining last known value.");
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSV I/O helper
// ─────────────────────────────────────────────────────────────────────────────

/// Append a single trade row to the session CSV file.
///
/// Creates the file with a header row if it does not exist. All I/O is done
/// via `tokio::fs` so it does not block the executor's async task.
async fn write_csv_row(
    filename:    &str,
    action:      &str,
    token_short: &str,
    shares:      f64,
    entry_price: f64,
    exit_price:  f64,
    trade_pnl:   f64,
    session_pnl: f64,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let file_exists = tokio::fs::metadata(filename).await.is_ok();

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)
        .await?;

    if !file_exists {
        let header = "Timestamp,Action,Token,Shares,Entry_VWAP,Exit_Price,Trade_PnL,Session_PnL\n";
        file.write_all(header.as_bytes()).await?;
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let row = format!(
        "{},{},{},{:.2},{:.4},{:.4},{:.2},{:.2}\n",
        timestamp,
        action,
        token_short,
        shares,
        entry_price,
        exit_price,
        trade_pnl,
        session_pnl,
    );

    file.write_all(row.as_bytes()).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Direction, MarketInfo, OrderBookSnapshot, SharedState, TriggerSnapshot};
    use std::time::Instant;

    fn init() {
        let _ = CONFIG.paper_mode;
    }

    fn make_state() -> Arc<SharedState> {
        let state = SharedState::new();
        let info = MarketInfo {
            token_id_up:   "TOKEN_UP".into(),
            token_id_down: "TOKEN_DOWN".into(),
            market_id:     "1".into(),
            market_slug:   "btc-updown-15m-test".into(),
            condition_id:  "0xCOND".into(),
            expiry_ts:     9_999_999_999,
            neg_risk:      true,
        };
        state.publish_market(info);
        state
    }

    fn make_snap(direction: Direction, effective_ask: f64) -> TriggerSnapshot {
        let book = OrderBookSnapshot {
            best_ask:     Some(effective_ask),
            best_bid:     Some(effective_ask - 0.02),
            opposing_bid: Some(1.0 - effective_ask - 0.01),
        };
        TriggerSnapshot {
            direction,
            delta:           55.0,
            trigger_instant: Instant::now(),
            exchange_ts:     1_750_000_000.0,
            book,
            token_id:        "TOKEN_UP".into(),
            market_slug:     "btc-updown-15m-test".into(),
            effective_ask,
            max_price:       (effective_ask * CONFIG.slippage_multiplier).min(0.99),
            spread:          Some(0.02),
            ev_breakdown:    "[Pen: 0.0 | ReqMom: 0.00]".into(),
            neg_risk:        true,
        }
    }

    // ── Position record ───────────────────────────────────────────────────────

    #[test]
    fn position_vwap_computed_on_construction() {
        let pos = Position::new(
            "tok".into(), 0.60, 100, Direction::Up, "slug".into(), "cond".into(), false,
        );
        assert!((pos.cost_basis - 0.60).abs() < f64::EPSILON);
        assert_eq!(pos.total_shares, 100);
        assert!((pos.total_spent - 60.0).abs() < f64::EPSILON);
    }

    #[test]
    fn position_add_fill_updates_vwap() {
        let mut pos = Position::new(
            "tok".into(), 0.60, 100, Direction::Up, "slug".into(), "cond".into(), false,
        );
        // Add 100 shares at 0.40 → new VWAP = (60 + 40) / 200 = 0.50
        pos.add_fill(0.40, 100);
        assert_eq!(pos.total_shares, 200);
        assert!((pos.cost_basis - 0.50).abs() < 1e-9);
    }

    #[test]
    fn position_take_profit_price_respects_ceiling() {
        init();
        let pos = Position::new(
            "tok".into(), 0.95, 100, Direction::Up, "slug".into(), "cond".into(), false,
        );
        // cost_basis * (1 + tp_pct) = 0.95 * 1.15 = 1.0925 → capped at EXIT_CEILING (0.98)
        let tp = pos.take_profit_price();
        assert!(tp <= CONFIG.exit_ceiling_price);
    }

    #[test]
    fn position_take_profit_price_normal_case() {
        init();
        let pos = Position::new(
            "tok".into(), 0.50, 100, Direction::Up, "slug".into(), "cond".into(), false,
        );
        // 0.50 * 1.15 = 0.575 < EXIT_CEILING (0.98)
        let tp = pos.take_profit_price();
        let expected = 0.50 * (1.0 + CONFIG.take_profit_pct);
        assert!((tp - expected.min(CONFIG.exit_ceiling_price)).abs() < 1e-9);
    }

    #[test]
    fn position_unrealised_pnl_correct() {
        let pos = Position::new(
            "tok".into(), 0.50, 100, Direction::Up, "slug".into(), "cond".into(), false,
        );
        // bid = 0.65 → pnl = (0.65 - 0.50) * 100 = 15.0
        let pnl = pos.unrealised_pnl(0.65);
        assert!((pnl - 15.0).abs() < 1e-9);
    }

    #[test]
    fn position_sell_cooldown_initial_true() {
        let pos = Position::new(
            "tok".into(), 0.50, 100, Direction::Up, "slug".into(), "cond".into(), false,
        );
        // No sell has occurred yet → cooldown is elapsed (should proceed).
        assert!(pos.sell_cooldown_elapsed());
    }

    // ── PaperLedger ───────────────────────────────────────────────────────────

    #[test]
    fn paper_ledger_credit_buy_adds_balance() {
        let mut ledger = PaperLedger::default();
        ledger.credit_buy("TOKEN_A", 100);
        assert_eq!(ledger.balance("TOKEN_A"), 100.0);
    }

    #[test]
    fn paper_ledger_debit_sell_reduces_balance() {
        let mut ledger = PaperLedger::default();
        ledger.credit_buy("TOKEN_A", 100);
        ledger.debit_sell("TOKEN_A", 40);
        assert_eq!(ledger.balance("TOKEN_A"), 60.0);
    }

    #[test]
    fn paper_ledger_debit_cannot_go_negative() {
        let mut ledger = PaperLedger::default();
        ledger.credit_buy("TOKEN_A", 10);
        ledger.debit_sell("TOKEN_A", 50); // Attempt to debit more than balance
        assert_eq!(ledger.balance("TOKEN_A"), 0.0);
    }

    #[test]
    fn paper_ledger_pnl_accumulates() {
        let mut ledger = PaperLedger::default();
        ledger.record_pnl(10.0);
        ledger.record_pnl(-3.0);
        assert!((ledger.session_pnl - 7.0).abs() < f64::EPSILON);
        assert!((ledger.window_pnl - 7.0).abs() < f64::EPSILON);
    }

    // ── ClobExecutor construction ─────────────────────────────────────────────

    #[test]
    fn executor_constructs_without_panic() {
        init();
        let state    = make_state();
        let executor = ClobExecutor::new(state);
        // Paper mode: bankroll should be initialised from config.
        if CONFIG.paper_mode {
            assert!(executor.bankroll() > 0.0);
        }
    }

    #[test]
    fn executor_bankroll_deduction_succeeds_with_funds() {
        init();
        let state    = make_state();
        let executor = ClobExecutor::new(state);
        let initial  = executor.bankroll();
        let result   = executor.deduct_bankroll(1.0);
        assert!(result, "should succeed with sufficient funds");
        assert!((executor.bankroll() - (initial - 1.0)).abs() < 1e-6);
    }

    #[test]
    fn executor_bankroll_deduction_fails_when_insufficient() {
        init();
        let state    = make_state();
        let executor = ClobExecutor::new(state);
        // Attempt to deduct more than the entire bankroll.
        let result = executor.deduct_bankroll(executor.bankroll() + 1000.0);
        assert!(!result, "should fail when bankroll is insufficient");
    }

    #[test]
    fn executor_credit_bankroll_adds_correctly() {
        init();
        let state    = make_state();
        let executor = ClobExecutor::new(state);
        let initial  = executor.bankroll();
        executor.credit_bankroll(50.0);
        assert!((executor.bankroll() - (initial + 50.0)).abs() < 1e-6);
    }

    // ── execute_trade: validation gates ──────────────────────────────────────

    #[tokio::test]
    async fn execute_trade_paper_rejects_too_small_order() {
        init();
        let state    = make_state();
        let executor = ClobExecutor::new(Arc::clone(&state));

        // Drain the bankroll to force a dust order.
        let drain = executor.bankroll() - 0.001; // Leave $0.001
        executor.deduct_bankroll(drain);

        // With $0.001 remaining and ask ≈ 0.50, buy_size = 0 → InsufficientBankroll.
        let snap = make_snap(Direction::Up, 0.50);
        let result = executor.execute_trade(&snap).await;
        assert!(matches!(result, Err(ExecutorError::InsufficientBankroll { .. })));
    }

    #[tokio::test]
    async fn execute_trade_paper_succeeds_with_sufficient_bankroll() {
        init();
        // Only run if PAPER_MODE is true (default).
        if !CONFIG.paper_mode {
            return;
        }
        let state    = make_state();
        let executor = ClobExecutor::new(Arc::clone(&state));

        let snap   = make_snap(Direction::Up, 0.40);
        let result = executor.execute_trade(&snap).await;

        assert!(result.is_ok(), "Paper trade should succeed: {:?}", result);
        let outcome = result.unwrap();
        assert!(outcome.success);
        assert!(outcome.fill_size > 0);
        assert!(outcome.fill_price > 0.0);
    }

    #[tokio::test]
    async fn execute_trade_paper_deducts_bankroll() {
        init();
        if !CONFIG.paper_mode {
            return;
        }
        let state    = make_state();
        let executor = ClobExecutor::new(Arc::clone(&state));

        let before = executor.bankroll();
        let snap   = make_snap(Direction::Up, 0.40);
        let _      = executor.execute_trade(&snap).await;
        let after  = executor.bankroll();

        assert!(after < before, "Bankroll should decrease after a paper buy.");
    }

    #[tokio::test]
    async fn execute_trade_paper_creates_position_record() {
        init();
        if !CONFIG.paper_mode {
            return;
        }
        let state    = make_state();
        let executor = ClobExecutor::new(Arc::clone(&state));

        let snap = make_snap(Direction::Up, 0.40);
        let _    = executor.execute_trade(&snap).await;

        let positions = executor.positions.lock();
        assert!(
            positions.contains_key("TOKEN_UP"),
            "Position record should be created after a fill."
        );
    }

    // ── Kelly fraction routing ────────────────────────────────────────────────

    #[test]
    fn kelly_fraction_routes_to_correct_tier() {
        init();
        // Tier A
        let fa = CONFIG.kelly_fraction(CONFIG.kelly_tier_a_score);
        assert!((fa - CONFIG.kelly_tier_a_fraction).abs() < f64::EPSILON);

        // Tier B
        let fb = CONFIG.kelly_fraction(CONFIG.kelly_tier_b_score);
        assert!((fb - CONFIG.kelly_tier_b_fraction).abs() < f64::EPSILON);

        // Tier C (below B)
        let fc = CONFIG.kelly_fraction(0.0);
        assert!((fc - CONFIG.kelly_tier_c_fraction).abs() < f64::EPSILON);
    }

    // ── wallet address derivation ─────────────────────────────────────────────

    #[test]
    fn wallet_address_stub_returns_none_for_empty_key() {
        assert!(crate::live_trading::derive_wallet_address("").is_none());
    }

    #[test]
    fn wallet_address_stub_returns_some_for_valid_length_key() {
        // 32 random bytes as hex = 64 hex chars.
        let fake_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let result = crate::live_trading::derive_wallet_address(fake_key);
        assert!(result.is_some());
    }

    #[test]
    fn wallet_address_stub_handles_0x_prefix() {
        let fake_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let result = crate::live_trading::derive_wallet_address(fake_key);
        assert!(result.is_some());
    }
}
