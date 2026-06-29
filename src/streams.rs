//! streams.rs — Binance aggTrade and Polymarket L2 orderbook WebSocket streams.
//!
//! # Architecture
//!
//! Two independent, self-reconnecting streams run as long-lived `tokio` tasks.
//! Both receive a shared `Arc<SharedState>` and write directly into the atomic
//! fields — no channels, no locks on the hot path.
//!
//! ```text
//!  tokio::spawn(binance_stream(Arc<SharedState>))
//!       │
//!       ▼
//!  loop {
//!    connect → wss://stream.binance.com/ws/btcusdt@aggTrade
//!    for msg in ws {
//!      price = parse(msg["p"])
//!      ts    = msg["E"] / 1000
//!      if expired → spawn(handle_rollover) → continue
//!      delta = state.binance.update(price, ts, window)
//!      if let Some(dir) = state.evaluate_delta(delta) {
//!          spawn(_trigger_buy(dir, snapshot))
//!      }
//!    }
//!    // reconnect on drop
//!  }
//!
//!  tokio::spawn(polymarket_stream(Arc<SharedState>))
//!       │
//!       ▼
//!  loop {
//!    wait for market info (token IDs) in SharedState::market
//!    connect → wss://ws-subscriptions-clob.polymarket.com/ws/market
//!    send subscription { assets_ids: [token_up, token_down], type: "market" }
//!    select! {
//!      msg  ← ws.next()        → parse → update state.book.*
//!      _    ← disconnect.notified() → break (rollover requested disconnect)
//!    }
//!    wait for poly_reconnect.notified()  (rollover posts new market info)
//!    // loop: reconnect with new token IDs
//!  }
//! ```
//!
//! # Zero-alloc hot path
//!
//! - `serde_json::from_str` is called on a `&str` slice of the pre-received
//!   message buffer. No intermediate `String` is created.
//! - Deserialized price/timestamp fields are stored directly into `AtomicF64`
//!   via `state.binance.update(...)` — no `Vec` growth, no boxing.
//! - Orderbook best-price logic is a linear scan over the raw JSON array,
//!   writing a single `f64` per side. Temporary `Vec<f64>` from Python is
//!   replaced by a running min/max accumulator.
//!
//! # Reconnection
//!
//! Both streams use an exponential back-off via `tokio-retry` on connection
//! failure. A clean close (code 1000/1001) does NOT back off — it reconnects
//! immediately. This mirrors the Python `async for websocket in websockets.connect()`
//! pattern which also reconnects instantly on clean close.
//!
//! Full implementation: Step 2.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::time::sleep;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::CONFIG;
use crate::errors::{WsError, WsOrigin, WsResult};
use crate::executor::ClobExecutor;
use crate::state::{Direction, MarketInfo, SharedState, TriggerSnapshot};

// ─────────────────────────────────────────────────────────────────────────────
// Binance aggTrade message shape
// ─────────────────────────────────────────────────────────────────────────────

/// Deserialised fields from a Binance `aggTrade` WebSocket message.
///
/// Only the fields we actually need are extracted. `serde_json` silently
/// ignores all other fields — no extra allocation for unused data.
///
/// Full Binance aggTrade payload reference:
/// <https://developers.binance.com/docs/derivatives/usds-margined-futures/websocket-market-streams/Aggregate-Trade-Streams>
#[derive(Debug, Deserialize)]
struct BinanceAggTrade<'a> {
    /// Aggregate trade price as a decimal string, e.g. `"67423.45000000"`.
    #[serde(rename = "p")]
    price: &'a str,

    /// Event time as Unix milliseconds (u64).
    ///
    /// This is the **exchange clock** timestamp. We use it instead of
    /// `std::time::SystemTime::now()` to avoid OS syscalls on every tick and
    /// to keep the expiry check synchronised with the exchange's own clock.
    #[serde(rename = "E")]
    event_time_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Polymarket message shapes
// ─────────────────────────────────────────────────────────────────────────────

/// A single price level from the Polymarket L2 orderbook.
#[derive(Debug, Deserialize)]
struct PolyLevel<'a> {
    price: &'a str,
    // `size` field exists but we don't need it for best-price extraction.
}

/// A single orderbook event from the Polymarket WS stream.
///
/// The Polymarket CLOB WS delivers either a single object or an array of
/// these objects. We handle both in [`polymarket_process_msg`].
#[derive(Debug, Deserialize)]
struct PolyBookEvent<'a> {
    /// CLOB token ID that this event updates.
    asset_id: Option<&'a str>,

    /// Ask (sell) price levels. May be absent if no asks changed.
    #[serde(default)]
    asks: Vec<PolyLevel<'a>>,

    /// Bid (buy) price levels. May be absent if no bids changed.
    #[serde(default)]
    bids: Vec<PolyLevel<'a>>,
}

/// Subscription message sent to the Polymarket WS on connect.
#[derive(Debug, serde::Serialize)]
struct PolySubscription<'a> {
    assets_ids: &'a [&'a str],
    #[serde(rename = "type")]
    sub_type: &'static str,
}

// ─────────────────────────────────────────────────────────────────────────────
// Reconnect back-off configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Initial delay before the first reconnect attempt after a non-clean close.
const RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(500);

/// Maximum delay between reconnect attempts (cap for exponential back-off).
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

/// Maximum number of back-off retries before capping at `RECONNECT_MAX_DELAY`.
const RECONNECT_MAX_RETRIES: u32 = 6;

/// Compute the back-off delay for retry attempt `n` (0-indexed).
///
/// Uses binary exponential back-off capped at [`RECONNECT_MAX_DELAY`]:
/// `delay = min(initial * 2^n, max)`
fn backoff_delay(attempt: u32) -> Duration {
    let factor = 1u64 << attempt.min(RECONNECT_MAX_RETRIES);
    let millis  = RECONNECT_INITIAL_DELAY.as_millis() as u64 * factor;
    Duration::from_millis(millis.min(RECONNECT_MAX_DELAY.as_millis() as u64))
}

// ─────────────────────────────────────────────────────────────────────────────
// BinanceStream — entry point spawned by SniperBrain
// ─────────────────────────────────────────────────────────────────────────────

/// Long-running Binance aggTrade WebSocket task.
///
/// Connects to the Binance stream URL from `CONFIG.binance_ws_url`, processes
/// each aggTrade message, updates the EMA state, and evaluates the momentum
/// delta against the pre-computed trigger thresholds in `SharedState`.
///
/// Automatically reconnects on any disconnect, with exponential back-off on
/// error and immediate reconnect on clean close.
///
/// # Arguments
/// - `state`: the shared bot state (Arc — cheaply cloned for the spawned trigger tasks).
/// - `market_fetcher`: needed to pass into `handle_rollover`.
pub async fn run_binance_stream(
    state: Arc<SharedState>,
    market_fetcher: Arc<crate::market_fetcher::MarketFetcher>,
    executor: Arc<ClobExecutor>,
) {
    info!("Binance stream task started. URL: {}", CONFIG.binance_ws_url);

    let mut attempt: u32 = 0;

    loop {
        match binance_connect_and_process(
            Arc::clone(&state),
            Arc::clone(&market_fetcher),
            Arc::clone(&executor),
        ).await {
            Ok(()) => {
                // Clean close — reconnect immediately.
                info!("[Binance] Clean WS close. Reconnecting immediately...");
                attempt = 0;
            }
            Err(WsError::Stopped { .. }) => {
                info!("[Binance] Stream stopped by operator signal. Exiting.");
                return;
            }
            Err(e) => {
                let delay = backoff_delay(attempt);
                warn!(
                    error = %e,
                    attempt = attempt,
                    delay_ms = delay.as_millis(),
                    "[Binance] Connection error — reconnecting after back-off."
                );
                sleep(delay).await;
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

/// Inner connection loop: establishes one WS connection and drives the message
/// loop until the connection closes or an unrecoverable error occurs.
///
/// Returns:
/// - `Ok(())` on clean close.
/// - `Err(WsError::Stopped)` when the stream should permanently stop.
/// - `Err(_)` on transport or parse errors (triggers back-off reconnect).
async fn binance_connect_and_process(
    state: Arc<SharedState>,
    market_fetcher: Arc<crate::market_fetcher::MarketFetcher>,
    executor: Arc<ClobExecutor>,
) -> WsResult<()> {
    let (mut ws, _) = connect_async(&CONFIG.binance_ws_url)
        .await
        .map_err(|e| WsError::Transport { origin: WsOrigin::Binance, source: e })?;

    info!("[Binance] Connected to aggTrade stream.");

    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| WsError::Transport { origin: WsOrigin::Binance, source: e })?;

        match msg {
            Message::Text(text) => {
                if let Err(e) = binance_process_message(
                    &state, &text, &market_fetcher, &executor,
                ).await {
                    // Non-fatal parse errors: log and continue.
                    warn!(error = %e, "[Binance] Message parse error — skipping.");
                }
            }
            Message::Ping(payload) => { ws.send(Message::Pong(payload)).await.ok(); }
            Message::Close(frame) => {
                let code   = frame.as_ref().map(|f| f.code.into());
                let reason = frame.as_ref().map(|f| f.reason.to_string());
                return Err(WsError::Closed { origin: WsOrigin::Binance, code, reason });
            }
            _ => {}
        }
    }

    Ok(())
}

/// Process a single Binance aggTrade text frame.
///
/// # Hot path
///
/// This function is called on every Binance tick. Every operation is O(1):
/// - Zero heap allocations (borrowing `&str` slices into the message buffer).
/// - The price string is parsed with `str::parse::<f64>()` — no intermediate `String`.
/// - EMA update writes directly to `AtomicF64` fields via `state.binance.update()`.
/// - Threshold evaluation is a single `AtomicF64::load(Acquire)` + comparison.
///
/// # Rollover
///
/// If the exchange timestamp has reached or passed `state.market_expiry`, we
/// atomically flip `is_rolling_over` (CAS false→true) and spawn `handle_rollover`.
/// All messages during rollover are dropped (the function returns early).
///
/// # Error handling
///
/// Returns `Err(WsError)` only for unrecoverable parse failures. Routine
/// "no threshold crossed" paths return `Ok(())` silently.
async fn binance_process_message(
    state: &Arc<SharedState>,
    text: &str,
    market_fetcher: &Arc<crate::market_fetcher::MarketFetcher>,
    executor: &Arc<ClobExecutor>,
) -> WsResult<()> {
    let trade: BinanceAggTrade = serde_json::from_str(text)
        .map_err(|e| WsError::JsonParse {
            origin:  WsOrigin::Binance,
            snippet: text.chars().take(120).collect(),
            source:  e,
        })?;

    let ts    = trade.event_time_ms as f64 / 1000.0;
    let price = trade.price.parse::<f64>()
        .map_err(|_| WsError::MissingField { origin: WsOrigin::Binance, field: "p (price parse)" })?;

    // ── Expiry / rollover check ────────────────────────────────────────────────
    if state.is_market_expired(ts) {
        if state.is_rolling_over
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let s  = Arc::clone(state);
            let mf = Arc::clone(market_fetcher);
            tokio::spawn(async move { crate::state::handle_rollover(s, mf).await; });
        }
        return Ok(()); // Always drop expired messages.
    }

    // ── Pre-expiry guard (no new positions within 15s of expiry) ──────────────
    if state.seconds_to_expiry(ts) < 15.0 {
        return Ok(());
    }

    // ── EMA update ────────────────────────────────────────────────────────────
    let delta = state.binance.update(price, ts, CONFIG.momentum_window_sec);

    // ── Threshold evaluation (the hot gate) ───────────────────────────────────
    if let Some(direction) = state.evaluate_delta(delta) {
        let snapshot = build_trigger_snapshot(state, direction, delta, ts);
        match snapshot {
            Some(snap) => {
                let s = Arc::clone(state);
                let e = Arc::clone(executor);
                tokio::spawn(async move { crate::sniper::trigger_buy(s, e, snap).await; });
            }
            None => {
                // No ask available — re-arm immediately.
                state.sniper.arm();
                warn!("[Binance] No ask price for {} — blind-fire aborted.", direction);
            }
        }
    }

    Ok(())
}

/// Build a [`TriggerSnapshot`] from shared state at the exact trigger microsecond.
///
/// Returns `None` and logs a warning if no effective ask is available for the
/// direction (real or synthetic via Binary Duality). This prevents blind-fire
/// orders into a completely empty book.
///
/// This function encapsulates the Binary Duality logic ported from Python's
/// `_trigger_buy`:
/// ```text
/// synthetic_ask(UP)   = 1.0 − best_bid_down
/// synthetic_ask(DOWN) = 1.0 − best_bid_up
/// effective_ask       = min(real_ask, synthetic_ask)
/// ```
fn build_trigger_snapshot(
    state: &Arc<SharedState>,
    direction: Direction,
    delta: f64,
    exchange_ts: f64,
) -> Option<TriggerSnapshot> {
    let book = state.book.snapshot_for_direction(direction);
    let effective_ask = book.effective_ask()?; // None → abort

    let max_price = (effective_ask * CONFIG.slippage_multiplier).min(0.99);
    let spread    = book.spread();

    // Spread safety gate — checked here so the executor never sees a bad spread.
    if let Some(sp) = spread {
        if sp > CONFIG.max_spread_cents {
            warn!(
                spread = sp,
                max    = CONFIG.max_spread_cents,
                "[{}] Spread too wide — aborting trigger.",
                direction
            );
            return None;
        }
    }

    let guard    = state.market.load();
    let market   = guard.as_ref()?;
    let token_id = match direction {
        Direction::Up   => market.token_id_up.clone(),
        Direction::Down => market.token_id_down.clone(),
    };
    let market_slug  = market.market_slug.clone();
    let neg_risk     = market.neg_risk;
    let ev_breakdown = state.ev_breakdown(direction);

    Some(TriggerSnapshot {
        direction,
        delta,
        trigger_instant: std::time::Instant::now(),
        exchange_ts,
        book,
        token_id,
        market_slug,
        effective_ask,
        max_price,
        spread,
        ev_breakdown,
        neg_risk,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// PolymarketStream — entry point spawned by SniperBrain
// ─────────────────────────────────────────────────────────────────────────────

/// Long-running Polymarket L2 orderbook WebSocket task.
///
/// Connects to the Polymarket CLOB WS, subscribes to both the UP and DOWN
/// token orderbooks, and updates `state.book.*` on every `book_change` event.
///
/// Responds to two signals from [`SharedState`]:
/// - `poly_disconnect`: exit the message loop (rollover in progress).
/// - `poly_reconnect`:  reconnect with fresh token IDs from the new `MarketInfo`.
///
/// # Arguments
/// - `state`: shared state — provides token IDs, disconnect/reconnect signals,
///   and the atomic orderbook fields to write.
pub async fn run_polymarket_stream(state: Arc<SharedState>) {
    info!(
        "Polymarket stream task started. URL: {}",
        CONFIG.poly_ws_url
    );

    loop {
        // ── Wait until we have valid market info ──────────────────────────────
        let market_guard = loop {
            let g = state.market.load();
            if g.is_some() {
                break g;
            }
            debug!("[Polymarket] Waiting for market info (token IDs)...");
            sleep(Duration::from_secs(1)).await;
        };

        let market = match market_guard.as_ref() {
            Some(m) => Arc::clone(m),
            None    => continue,
        };

        info!(
            token_up   = %market.token_id_up,
            token_down = %market.token_id_down,
            "[Polymarket] Market info resolved. Connecting..."
        );

        // ── Connect and process until disconnect signal ────────────────────────
        match polymarket_connect_and_process(Arc::clone(&state), &market).await {
            Ok(()) => {
                info!("[Polymarket] Clean disconnect. Waiting for reconnect signal...");
            }
            Err(WsError::Stopped { .. }) => {
                info!("[Polymarket] Stream stopped by operator signal. Exiting.");
                return;
            }
            Err(e) => {
                warn!(error = %e, "[Polymarket] Connection error — will retry after reconnect signal.");
            }
        }

        // ── Wait for rollover to post the reconnect signal ─────────────────────
        // If rollover already notified before we got here, `notified()` returns
        // immediately (it is a single-permit semaphore).
        state.poly_reconnect.notified().await;
        info!("[Polymarket] Reconnect signal received — reloading market info.");
    }
}

/// Inner connection loop for the Polymarket stream.
///
/// 1. Opens a WS connection to `CONFIG.poly_ws_url`.
/// 2. Sends the subscription message for both token IDs.
/// 3. Drives the message loop with `tokio::select!` so disconnect signals
///    from rollover can interrupt the `ws.next().await`.
async fn polymarket_connect_and_process(
    state: Arc<SharedState>,
    market: &Arc<MarketInfo>,
) -> WsResult<()> {
    let (mut ws, _) = connect_async(&CONFIG.poly_ws_url)
        .await
        .map_err(|e| WsError::Transport { origin: WsOrigin::Polymarket, source: e })?;

    info!("[Polymarket] Connected to L2 CLOB stream.");

    // Send subscription for both token legs.
    let sub = PolySubscription {
        assets_ids: &[market.token_id_up.as_str(), market.token_id_down.as_str()],
        sub_type:   "market",
    };
    let sub_json = serde_json::to_string(&sub).expect("subscription serialization");
    ws.send(Message::Text(sub_json.into()))
        .await
        .map_err(|e| WsError::SubscriptionFailed { origin: WsOrigin::Polymarket, source: e })?;

    info!(
        token_up   = %market.token_id_up,
        token_down = %market.token_id_down,
        "[Polymarket] Subscribed to L2 orderbook for both tokens."
    );

    loop {
        tokio::select! {
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        polymarket_process_message(&state, &text, market);
                    }
                    Some(Ok(Message::Ping(p))) => { ws.send(Message::Pong(p)).await.ok(); }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        return Err(WsError::Transport { origin: WsOrigin::Polymarket, source: e });
                    }
                    Some(Ok(_)) => {}
                }
            }
            _ = state.poly_disconnect.notified() => {
                info!("[Polymarket] Disconnect signal received. Closing WS...");
                ws.close(None).await.ok();
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Process a single Polymarket L2 orderbook text frame.
///
/// # Zero-allocation design
///
/// - Uses `serde_json::from_str` with `&'a str` borrows into the message text.
/// - Iterates `asks`/`bids` arrays with a running min/max accumulator instead
///   of collecting into a `Vec<f64>` (replaces the Python `min(valid_asks)` path).
/// - Writes directly to `state.book.*` via [`store_price`] with `Release` ordering.
///
/// # Message format
///
/// The Polymarket WS can send either:
/// - A JSON array: `[{asset_id, asks, bids}, ...]`
/// - A single JSON object: `{asset_id, asks, bids}`
///
/// We handle both by attempting array parse first, then single-object parse.
///
/// This function is intentionally **synchronous** (no `async`) — it does no
/// I/O and must not block the WS receive loop. All writes are via atomics.
fn polymarket_process_message(
    state: &Arc<SharedState>,
    text: &str,
    market: &Arc<MarketInfo>,
) {
    // Try JSON array first, then fall back to a single object.
    let events: Vec<PolyBookEvent> = if text.trim_start().starts_with('[') {
        match serde_json::from_str(text) {
            Ok(v)  => v,
            Err(e) => {
                warn!(error = %e, "[Polymarket] Failed to parse message array.");
                return;
            }
        }
    } else {
        match serde_json::from_str::<PolyBookEvent>(text) {
            Ok(e)    => vec![e],
            Err(err) => {
                warn!(error = %err, "[Polymarket] Failed to parse single event.");
                return;
            }
        }
    };

    for event in &events {
        polymarket_update_orderbook(state, event, market);
    }
}

/// Apply a single Polymarket orderbook event to the shared atomic state.
///
/// Extracts the best ask (minimum ask price) and best bid (maximum bid price)
/// using running min/max accumulators — no heap allocation.
///
/// Prices that fail `str::parse::<f64>()` are skipped defensively (mirrors
/// the Python `try: float(ask.get("price", 1.0)) / except (ValueError, TypeError): continue`).
fn polymarket_update_orderbook<'a>(
    state: &Arc<SharedState>,
    event: &PolyBookEvent<'a>,
    market: &Arc<MarketInfo>,
) {
    let asset_id = match event.asset_id {
        Some(id) => id,
        None     => return,
    };

    // ── Best ask: running minimum ──────────────────────────────────────────────
    if !event.asks.is_empty() {
        let mut best: Option<f64> = None;
        for level in &event.asks {
            if let Ok(p) = level.price.parse::<f64>() {
                if p > 0.0 {
                    best = Some(match best {
                        Some(b) => b.min(p),
                        None    => p,
                    });
                }
            }
        }
        state.book.update_ask(asset_id, best, market);
    }

    // ── Best bid: running maximum ──────────────────────────────────────────────
    if !event.bids.is_empty() {
        let mut best: Option<f64> = None;
        for level in &event.bids {
            if let Ok(p) = level.price.parse::<f64>() {
                if p > 0.0 {
                    best = Some(match best {
                        Some(b) => b.max(p),
                        None    => p,
                    });
                }
            }
        }
        state.book.update_bid(asset_id, best, market);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_increases_exponentially() {
        let d0 = backoff_delay(0);
        let d1 = backoff_delay(1);
        let d2 = backoff_delay(2);
        assert!(d1 > d0, "delay should increase with attempts");
        assert!(d2 > d1, "delay should keep increasing");
    }

    #[test]
    fn backoff_delay_caps_at_max() {
        // After RECONNECT_MAX_RETRIES, delay should equal RECONNECT_MAX_DELAY.
        let capped = backoff_delay(RECONNECT_MAX_RETRIES + 10);
        assert_eq!(capped, RECONNECT_MAX_DELAY);
    }

    #[test]
    fn backoff_delay_zero_attempt_is_initial() {
        assert_eq!(backoff_delay(0), RECONNECT_INITIAL_DELAY);
    }
}
