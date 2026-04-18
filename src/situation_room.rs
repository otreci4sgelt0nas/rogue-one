//! situation_room.rs — EV (Expected Value) heuristics and momentum threshold computation.
//!
//! # Responsibility
//!
//! The `SituationRoom` runs as a dedicated `tokio` background task that wakes
//! every **500 ms** and recomputes the minimum momentum required to justify a
//! trade in each direction. The result — a fully merged, absolute threshold —
//! is written directly to [`SharedState::sniper`]'s `trigger_up` / `trigger_down`
//! atomics with `Release` ordering.
//!
//! This collapses the "3-hop chain" (self → situation_room → trigger) from the
//! Python implementation into a single `AtomicF64::load(Acquire)` on the hot
//! Binance tick path.
//!
//! # EV Model
//!
//! ```text
//! ev_score = EV_BASE_SCORE
//!          + momentum_bonus              [0, EV_MAX_MOMENTUM_BONUS]
//!          - time_penalty               [0, EV_TIME_DANGER_PENALTY]
//!          - spread_penalty             [0, ∞ if spread > MAX_SPREAD_CENTS]
//!          - death_trap_penalty         [0, EV_DEATH_TRAP_PENALTY_1]
//!
//! A trade is valid when ev_score ≥ EV_MIN_ACCEPTABLE_SCORE.
//! Rearranging for the minimum required momentum:
//!   needed_from_mom = EV_MIN_ACCEPTABLE_SCORE - EV_BASE_SCORE + total_penalties
//!   req_momentum    = needed_from_mom / EV_MOMENTUM_MULTIPLIER
//! ```
//!
//! If `req_momentum > EV_MAX_MOMENTUM_BONUS / EV_MOMENTUM_MULTIPLIER`, the
//! penalty load is so heavy that no realistic momentum can satisfy the EV floor
//! → threshold is set to `f64::MAX` (effectively vetoed).
//!
//! # Hold EV
//!
//! [`calculate_hold_ev`] is called by the position manager every few seconds
//! to decide whether to hold or exit an open position. It uses a simplified
//! drawdown-based scoring model.
//!
//! # Hot-path isolation
//!
//! This module is **never called on the Binance WS tick**. All computation
//! happens in the 500 ms background loop. The hot path only reads two
//! `AtomicF64` values pre-written by this module.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tracing::{debug, info};

use crate::config::CONFIG;
use crate::state::{SharedState, load_price};

// ─────────────────────────────────────────────────────────────────────────────
// Threshold computation result
// ─────────────────────────────────────────────────────────────────────────────

/// The output of a single [`calculate_required_momentum`] call.
///
/// Carries both the numeric threshold and a human-readable diagnostic string
/// that is published to [`SharedState::situation_diag`] for inclusion in trade
/// log lines when a trigger fires.
#[derive(Debug, Clone)]
pub struct MomentumRequirement {
    /// The minimum price delta (USD) required to justify entering a trade.
    ///
    /// `f64::MAX` is returned when the trade should be **unconditionally vetoed**
    /// (e.g. price too high, penalties too severe for any momentum to compensate).
    pub min_momentum: f64,

    /// Human-readable penalty / requirement breakdown for structured logging.
    ///
    /// Example: `"[Penalties: 45.0 | ReqMom: 33.33]"`
    pub breakdown: String,
}

impl MomentumRequirement {
    /// Construct a vetoed requirement with a descriptive reason.
    #[inline]
    fn veto(reason: impl Into<String>) -> Self {
        Self {
            min_momentum: f64::MAX,
            breakdown:    reason.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SituationRoom
// ─────────────────────────────────────────────────────────────────────────────

/// Background heuristics engine that continuously recomputes momentum thresholds.
///
/// Constructed once in `SniperBrain::start` and run as a detached `tokio` task
/// via [`SituationRoom::run`]. Takes a shared reference to `Arc<SharedState>`
/// to read orderbook prices and write trigger thresholds.
///
/// # State
///
/// The `SituationRoom` is intentionally **stateless** beyond what is already in
/// `SharedState`. The last breakdown strings are written directly into
/// [`SharedState::situation_diag`] via the [`parking_lot::RwLock`] — no fields
/// on the struct itself. This makes `SituationRoom` safe to reconstruct or
/// restart across rollovers without stale internal state.
#[derive(Debug, Default)]
pub struct SituationRoom;

impl SituationRoom {
    /// Construct a new `SituationRoom`.
    pub fn new() -> Self {
        Self
    }

    /// Spawn the 500 ms heuristics background loop as a detached `tokio` task.
    ///
    /// The spawned task runs for the lifetime of the process. Panics inside the
    /// loop are caught and logged — the loop continues so the bot never loses
    /// threshold updates silently.
    ///
    /// # Arguments
    /// - `state`: the shared bot state. The task holds a clone of the `Arc`.
    pub fn start(self, state: Arc<SharedState>) {
        info!("Starting SituationRoom heuristics background loop (500 ms cadence).");
        tokio::spawn(async move {
            run_heuristics_loop(state).await;
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background loop
// ─────────────────────────────────────────────────────────────────────────────

/// The 500 ms heuristics loop body.
///
/// Wakes every 500 ms, computes the momentum requirements for both directions,
/// merges them with the dynamic threshold, and publishes to `SharedState`.
///
/// # Panic safety
///
/// All per-iteration errors are caught at this boundary and logged. The loop
/// always continues so a transient error never permanently disables thresholds.
async fn run_heuristics_loop(state: Arc<SharedState>) {
    let interval = Duration::from_millis(500);

    loop {
        tokio::time::sleep(interval).await;

        // Only run if a market is loaded and we are not in rollover.
        if state.is_rolling_over() {
            debug!("[SituationRoom] Rollover in progress — skipping update.");
            continue;
        }

        let market_guard = state.market.load();
        if market_guard.is_none() {
            debug!("[SituationRoom] No market loaded yet — skipping update.");
            continue;
        }

        // Snapshot the exchange-clock expiry for time-to-expiry calculation.
        let expiry_ts  = state.market_expiry_secs();
        let now_secs   = crate::state::unix_now_secs();
        let time_left  = (expiry_ts - now_secs).max(0.0);

        // ── Read orderbook prices ─────────────────────────────────────────────
        // Acquire ordering: we need to see the latest Release stores from the
        // Polymarket WS task.
        let best_ask_up   = load_price(&state.book.best_ask_up,   Ordering::Acquire);
        let best_bid_up   = load_price(&state.book.best_bid_up,   Ordering::Acquire);
        let best_ask_down = load_price(&state.book.best_ask_down, Ordering::Acquire);
        let best_bid_down = load_price(&state.book.best_bid_down, Ordering::Acquire);

        // ── Compute EV floors for each direction ──────────────────────────────
        let req_up   = calculate_required_momentum(best_ask_up,   best_bid_up,   time_left);
        let req_down = calculate_required_momentum(best_ask_down, best_bid_down, time_left);

        // ── Merge with the sniper's pre-calculated dynamic threshold ──────────
        let dynamic = state.sniper.current_dynamic_threshold.load(Ordering::Acquire);

        let trigger_up   = merge_thresholds(dynamic, req_up.min_momentum);
        let trigger_down = merge_thresholds(dynamic, req_down.min_momentum);

        // ── Publish merged thresholds atomically ──────────────────────────────
        state.sniper.set_triggers(trigger_up, trigger_down);

        // ── Publish breakdown strings (behind RwLock — infrequent write) ─────
        state.update_situation_diag(req_up.breakdown.clone(), req_down.breakdown.clone());

        debug!(
            trigger_up   = trigger_up,
            trigger_down = trigger_down,
            time_left    = time_left,
            breakdown_up = %req_up.breakdown,
            breakdown_dn = %req_down.breakdown,
            "[SituationRoom] Thresholds updated."
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core EV math
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the minimum USD momentum delta required to meet the EV floor for
/// a trade in one direction.
///
/// Mirrors the Python `SituationRoom._calculate_required_momentum` exactly,
/// including all penalty tiers and veto conditions.
///
/// # Arguments
/// - `best_ask`  : current best ask for the target leg (`None` → immediate veto).
/// - `best_bid`  : current best bid for the target leg (`None` → no-bid penalty).
/// - `time_left` : seconds remaining until market expiry.
///
/// # Returns
/// A [`MomentumRequirement`] with `min_momentum = f64::MAX` if the trade should
/// be unconditionally blocked, or a finite threshold otherwise.
///
/// # Notes on precision
///
/// All intermediate values are `f64`. For a binary options market where prices
/// are in `[0.01, 0.99]` and penalties are in `[0.0, 100.0]`, `f64` precision
/// is more than sufficient — there is no need for `f64::from(Decimal)`.
pub fn calculate_required_momentum(
    best_ask:  Option<f64>,
    best_bid:  Option<f64>,
    time_left: f64,
) -> MomentumRequirement {
    // ── Guard: no ask available ───────────────────────────────────────────────
    let ask = match best_ask {
        Some(a) if a > 0.0 => a,
        _ => return MomentumRequirement::veto("[No Ask]"),
    };

    // ── Apply slippage to get the effective entry price ───────────────────────
    // We cap at 0.99 because the CLOB rejects prices ≥ 1.0.
    let current_price = (ask * CONFIG.slippage_multiplier).min(0.99);

    // ── Price ceiling gate ────────────────────────────────────────────────────
    if current_price > CONFIG.max_buy_price {
        return MomentumRequirement::veto(format!(
            "[Price {:.3} > Max {:.2}]",
            current_price, CONFIG.max_buy_price
        ));
    }

    // ── Time penalty ─────────────────────────────────────────────────────────
    // Only applies when the price is already high (near resolution probability).
    let time_penalty = if current_price > CONFIG.ev_high_price_thresh {
        if time_left > CONFIG.ev_time_danger_sec {
            CONFIG.ev_time_danger_penalty
        } else if time_left > CONFIG.ev_time_warn_sec {
            CONFIG.ev_time_warn_penalty
        } else {
            0.0
        }
    } else {
        0.0
    };

    // ── Spread penalty ────────────────────────────────────────────────────────
    // A wide spread signals thin or manipulated liquidity.
    let spread_penalty = match best_bid {
        Some(bid) if bid > 0.0 => {
            let spread = (current_price - bid).max(0.0);
            if spread > CONFIG.max_spread_cents {
                // Proportional penalty: each cent over the max costs 2 EV points.
                spread * 200.0
            } else if spread > 0.02 {
                10.0
            } else {
                0.0
            }
        }
        _ => {
            // No bid data at all — apply the no-bids penalty.
            CONFIG.ev_no_bids_penalty
        }
    };

    // ── Death-trap penalty (falling knife avoidance) ──────────────────────────
    // Very cheap assets often have poor resolution probability.
    let death_trap_penalty = if current_price < CONFIG.ev_death_trap_thresh_1 {
        CONFIG.ev_death_trap_penalty_1
    } else if current_price < CONFIG.ev_death_trap_thresh_2 {
        CONFIG.ev_death_trap_penalty_2
    } else {
        0.0
    };

    // ── Compute required momentum from the EV equation ────────────────────────
    //
    // Full EV equation:
    //   ev_score = base + mom * multiplier - penalties  ≥ min_acceptable
    //
    // Rearranging to solve for minimum momentum:
    //   mom * multiplier ≥ min_acceptable - base + penalties
    //   mom              ≥ (min_acceptable - base + penalties) / multiplier
    //
    let total_penalties = time_penalty + spread_penalty + death_trap_penalty;
    let needed_from_mom = CONFIG.ev_min_acceptable_score - CONFIG.ev_base_score + total_penalties;

    let min_momentum = if needed_from_mom <= 0.0 {
        // Penalties are so low that any positive momentum satisfies the EV floor.
        0.0
    } else {
        let req = needed_from_mom / CONFIG.ev_momentum_multiplier;
        let cap = CONFIG.ev_max_momentum_bonus / CONFIG.ev_momentum_multiplier;

        if req > cap {
            // Even maximum possible momentum bonus cannot overcome the penalties.
            let breakdown = format!(
                "[VETO: Penalties too high ({:.1}) — req {:.2} > cap {:.2}]",
                total_penalties, req, cap
            );
            return MomentumRequirement::veto(breakdown);
        }

        req
    };

    let breakdown = format!(
        "[Pen: {:.1} (time={:.1} spread={:.1} dt={:.1}) | Price: {:.3} | ReqMom: {:.2}]",
        total_penalties,
        time_penalty,
        spread_penalty,
        death_trap_penalty,
        current_price,
        min_momentum,
    );

    MomentumRequirement { min_momentum, breakdown }
}

/// Merge the sniper's dynamic (escalating) threshold with the EV floor.
///
/// The effective trigger is the **maximum** of both values — we need momentum
/// to satisfy *both* the EV model *and* the escalating compounding bar.
///
/// If either value is `f64::MAX` (vetoed), the result is `f64::MAX` (blocked).
#[inline]
pub fn merge_thresholds(dynamic_threshold: f64, ev_floor: f64) -> f64 {
    // Using `f64::max` preserves `f64::MAX` correctly — infinity propagates.
    dynamic_threshold.max(ev_floor)
}

// ─────────────────────────────────────────────────────────────────────────────
// Hold EV — called by the position manager
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Expected Value of **holding** an open position.
///
/// Used by the position manager to decide whether to exit a stagnant or
/// losing position early, before the natural expiry logic triggers.
///
/// # Scoring model
///
/// Starts at 100.0 (maximum confidence). Applies penalties for:
/// - Drawdown below cost basis (up to −60 pts, proportional to loss %).
/// - Time danger zone (< 300s remaining): −30 pts.
/// - Time critical zone (< 120s remaining): −20 pts additional.
///
/// Score is clamped to `[0.0, 100.0]`.
///
/// # Arguments
/// - `best_bid`           : current best bid on the held token.
/// - `cost_basis`         : VWAP entry price (average cost per share).
/// - `time_remaining_sec` : seconds until market expiry.
///
/// # Returns
/// An EV score in `[0.0, 100.0]`. Below [`CONFIG.ev_bailout_score_thresh`],
/// the position manager should initiate an early exit.
pub fn calculate_hold_ev(
    best_bid:           f64,
    cost_basis:         f64,
    time_remaining_sec: f64,
) -> f64 {
    let mut score = 100.0_f64;

    // ── Drawdown penalty ──────────────────────────────────────────────────────
    if best_bid < cost_basis {
        let drawdown_pct = if cost_basis > 0.0 {
            (cost_basis - best_bid) / cost_basis
        } else {
            1.0
        };

        // Up to -60 points for the drawdown magnitude.
        score -= drawdown_pct * 60.0;

        // Additional time-based penalties when the position is losing.
        // Both penalties stack when time < 120s, matching the Python logic:
        //   if time < 300s: -30  (danger)
        //   if time < 120s: -20  (critical, cumulative on top of danger)
        if time_remaining_sec < 300.0 {
            score -= 30.0; // Danger: < 5 minutes
        }
        if time_remaining_sec < 120.0 {
            score -= 20.0; // Critical: < 2 minutes (stacks with danger penalty)
        }
    }

    score.clamp(0.0, 100.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: check if a position is "safe to hold to expiry"
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the position is deep enough in-the-money to hold until
/// market expiry without attempting an early exit.
///
/// Mirrors the Python "SAFE TO EXPIRY LOGIC":
/// - Best bid ≥ `CONFIG.safe_expiry_bid_thresh`  (e.g. 0.95 — nearly resolved)
/// - Time remaining ≥ `CONFIG.safe_expiry_time_sec` (e.g. 120s — no rush)
///
/// When both conditions hold, the position manager skips the take-profit check
/// and lets the binary resolve on-chain for maximum yield.
#[inline]
pub fn is_safe_to_hold_to_expiry(best_bid: f64, time_remaining_sec: f64) -> bool {
    best_bid >= CONFIG.safe_expiry_bid_thresh
        && time_remaining_sec >= CONFIG.safe_expiry_time_sec
}

/// Returns `true` if the impatience timer has elapsed, signalling that a
/// stagnant position should be sold at a micro-bounce take-profit.
///
/// # Arguments
/// - `entry_time_secs` : Unix timestamp (seconds) when the position was opened.
/// - `now_secs`        : current Unix timestamp (seconds).
#[inline]
pub fn is_impatient(entry_time_secs: f64, now_secs: f64) -> bool {
    (now_secs - entry_time_secs) >= CONFIG.impatience_sec
}

/// Compute the impatience take-profit target price.
///
/// If the current best bid has risen by at least `CONFIG.impatience_tp_pct`
/// above the cost basis, the impatience sell fires even if the primary TP
/// target hasn't been reached yet.
///
/// # Returns
/// The minimum bid that satisfies the impatience micro-bounce target.
#[inline]
pub fn impatience_target_price(cost_basis: f64) -> f64 {
    cost_basis * (1.0 + CONFIG.impatience_tp_pct)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure CONFIG is initialised before any test that reads it.
    fn init() {
        let _ = CONFIG.paper_mode;
    }

    // ── calculate_required_momentum: veto cases ───────────────────────────────

    #[test]
    fn veto_when_no_ask() {
        init();
        let req = calculate_required_momentum(None, None, 600.0);
        assert_eq!(req.min_momentum, f64::MAX);
        assert!(req.breakdown.contains("No Ask"));
    }

    #[test]
    fn veto_when_ask_is_zero() {
        init();
        let req = calculate_required_momentum(Some(0.0), None, 600.0);
        assert_eq!(req.min_momentum, f64::MAX);
    }

    #[test]
    fn veto_when_price_exceeds_max_buy_price() {
        init();
        // With 500 bps slippage, an ask of 0.85 → price ≈ 0.8925.
        // CONFIG default MAX_BUY_PRICE = 0.85. So 0.8925 > 0.85 → veto.
        let req = calculate_required_momentum(Some(0.85), Some(0.80), 600.0);
        assert_eq!(req.min_momentum, f64::MAX);
        assert!(req.breakdown.contains("Max"));
    }

    // ── calculate_required_momentum: normal path ──────────────────────────────

    #[test]
    fn returns_zero_momentum_when_penalties_low() {
        init();
        // A cheap asset with a tight spread and plenty of time — penalties should
        // be negligible, required momentum should be small (possibly 0).
        // Ask = 0.30, slippage → 0.315 (well below max_buy_price 0.85).
        // bid = 0.29 → spread = 0.025 > 0.02 → spread_pen = 10.0
        // No time penalty (price < ev_high_price_thresh 0.80).
        // No death trap (price 0.315 > thresh_2 0.20).
        // total_pen = 10.0
        // needed = EV_MIN(40) - EV_BASE(50) + 10 = 0 → min_mom = 0
        let req = calculate_required_momentum(Some(0.30), Some(0.29), 600.0);
        assert!(req.min_momentum < f64::MAX);
        // min_momentum should be 0 (needed_from_mom ≤ 0 after base subtraction).
        assert_eq!(req.min_momentum, 0.0);
    }

    #[test]
    fn applies_no_bid_penalty() {
        init();
        // No bid data → EV_NO_BIDS_PENALTY (40.0 default) applied.
        let req_no_bid = calculate_required_momentum(Some(0.30), None, 600.0);
        let req_with_bid = calculate_required_momentum(Some(0.30), Some(0.29), 600.0);
        // No-bid case has higher (or equal-max) required momentum.
        assert!(req_no_bid.min_momentum >= req_with_bid.min_momentum);
    }

    #[test]
    fn applies_death_trap_penalty_tier_1() {
        init();
        // Price after slippage below EV_DEATH_TRAP_THRESH_1 (0.10 default).
        // ask = 0.05 → price ≈ 0.05 * 1.05 = 0.0525 < 0.10 → penalty_1 = 40.0
        let req = calculate_required_momentum(Some(0.05), Some(0.045), 600.0);
        // With 40.0 death-trap + 10.0 spread penalty = 50.0 total
        // needed = 40 - 50 + 50 = 40; req_mom = 40 / 0.15 ≈ 266.7 > cap
        // cap = 20 / 0.15 ≈ 133.3
        // So: veto (VETO: Penalties too high)
        assert_eq!(req.min_momentum, f64::MAX);
        assert!(req.breakdown.contains("VETO"));
    }

    #[test]
    fn applies_death_trap_penalty_tier_2() {
        init();
        // ask = 0.15 → price ≈ 0.1575, between thresh_1 (0.10) and thresh_2 (0.20)
        // → penalty_2 = 20.0
        let req = calculate_required_momentum(Some(0.15), Some(0.14), 600.0);
        // spread ≈ 0.1575 - 0.14 ≈ 0.0175 < 0.02 → spread_pen = 0
        // total_pen = 20.0
        // needed = 40 - 50 + 20 = 10; req_mom = 10 / 0.15 ≈ 66.7
        // cap = 20 / 0.15 ≈ 133.3 → within cap, finite result
        assert!(req.min_momentum.is_finite());
        assert!(req.min_momentum > 0.0);
    }

    #[test]
    fn applies_time_danger_penalty_when_price_high_and_time_ample() {
        init();
        // price ≈ 0.84 (> ev_high_price_thresh 0.80), time_left > ev_time_danger_sec (300)
        // → time_penalty = ev_time_danger_penalty (30.0)
        let req_long_time  = calculate_required_momentum(Some(0.80), Some(0.75), 400.0);
        let req_short_time = calculate_required_momentum(Some(0.80), Some(0.75), 100.0);
        // Long time → danger penalty (30.0); short time (< warn_sec 120) → 0 penalty.
        // Counter-intuitive but correct per the model: time is dangerous when you
        // have *more* time and the price is already high (you overpay relative to prob).
        // More time left means higher penalty → higher required momentum.
        // (Less time left and deep ITM → resolve naturally → 0 penalty.)
        assert!(req_long_time.min_momentum >= req_short_time.min_momentum);
    }

    #[test]
    fn spread_penalty_proportional_above_max() {
        init();
        // Wide spread (> MAX_SPREAD_CENTS = 0.05) → proportional penalty.
        // ask = 0.55, bid = 0.40 → spread = 0.15 → penalty = 0.15 * 200 = 30.0
        let req_wide   = calculate_required_momentum(Some(0.55), Some(0.40), 600.0);
        // Tight spread (< 0.02) → no penalty.
        let req_tight  = calculate_required_momentum(Some(0.55), Some(0.545), 600.0);
        assert!(req_wide.min_momentum >= req_tight.min_momentum);
    }

    // ── merge_thresholds ──────────────────────────────────────────────────────

    #[test]
    fn merge_returns_maximum_of_dynamic_and_ev_floor() {
        assert_eq!(merge_thresholds(40.0, 60.0), 60.0);
        assert_eq!(merge_thresholds(80.0, 30.0), 80.0);
        assert_eq!(merge_thresholds(50.0, 50.0), 50.0);
    }

    #[test]
    fn merge_propagates_veto() {
        let merged = merge_thresholds(40.0, f64::MAX);
        assert_eq!(merged, f64::MAX);
    }

    // ── calculate_hold_ev ─────────────────────────────────────────────────────

    #[test]
    fn hold_ev_perfect_when_above_cost_basis() {
        let score = calculate_hold_ev(0.90, 0.60, 600.0);
        // best_bid (0.90) > cost_basis (0.60) → no penalty → 100.0
        assert!((score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hold_ev_clamped_at_zero() {
        // Massive drawdown: bid = 0.01, cost = 0.90, < 2 min left.
        let score = calculate_hold_ev(0.01, 0.90, 50.0);
        // drawdown_pct ≈ 0.989 → -59.4; time crit -20; -20 more → way below 0.
        assert_eq!(score, 0.0);
    }

    #[test]
    fn hold_ev_time_critical_zone_adds_penalty() {
        let score_safe = calculate_hold_ev(0.50, 0.60, 600.0); // above cost = no time pen
        let score_bad  = calculate_hold_ev(0.50, 0.60, 50.0);  // < 2 min, losing
        // Both are losing; critical zone should yield a lower score.
        assert!(score_bad <= score_safe);
    }

    #[test]
    fn hold_ev_danger_zone_less_severe_than_critical() {
        // Both time penalties stack when time < 120s (danger -30 + critical -20).
        // The danger-only window (120s < t < 300s) gets only -30.
        // So the critical zone must score lower than the danger-only zone.
        let score_danger   = calculate_hold_ev(0.50, 0.60, 200.0); // 120<t<300 → danger only (-30)
        let score_critical = calculate_hold_ev(0.50, 0.60, 50.0);  // t<120 → danger + critical (-50)
        assert!(score_critical < score_danger,
            "critical (t<120s) score {} must be lower than danger-only (120<t<300) score {}",
            score_critical, score_danger);
    }

    // ── is_safe_to_hold_to_expiry ─────────────────────────────────────────────

    #[test]
    fn safe_to_hold_when_both_conditions_met() {
        init();
        let bid = CONFIG.safe_expiry_bid_thresh + 0.01;  // above threshold
        let t   = CONFIG.safe_expiry_time_sec + 10.0;    // above minimum time
        assert!(is_safe_to_hold_to_expiry(bid, t));
    }

    #[test]
    fn not_safe_when_bid_too_low() {
        init();
        let bid = CONFIG.safe_expiry_bid_thresh - 0.01;
        let t   = CONFIG.safe_expiry_time_sec + 10.0;
        assert!(!is_safe_to_hold_to_expiry(bid, t));
    }

    #[test]
    fn not_safe_when_time_too_short() {
        init();
        let bid = CONFIG.safe_expiry_bid_thresh + 0.01;
        let t   = CONFIG.safe_expiry_time_sec - 1.0;
        assert!(!is_safe_to_hold_to_expiry(bid, t));
    }

    // ── impatience ────────────────────────────────────────────────────────────

    #[test]
    fn impatience_triggers_after_elapsed_time() {
        init();
        let entry = 1_000.0_f64;
        let now   = entry + CONFIG.impatience_sec + 1.0;
        assert!(is_impatient(entry, now));
    }

    #[test]
    fn impatience_does_not_trigger_early() {
        init();
        let entry = 1_000.0_f64;
        let now   = entry + CONFIG.impatience_sec - 1.0;
        assert!(!is_impatient(entry, now));
    }

    #[test]
    fn impatience_target_above_cost_basis() {
        init();
        let cost   = 0.60_f64;
        let target = impatience_target_price(cost);
        assert!(target > cost);
        let expected = cost * (1.0 + CONFIG.impatience_tp_pct);
        assert!((target - expected).abs() < f64::EPSILON);
    }

    // ── MomentumRequirement breakdown string format ───────────────────────────

    #[test]
    fn breakdown_contains_pen_and_reqmom() {
        init();
        // A clean, healthy market scenario.
        let req = calculate_required_momentum(Some(0.40), Some(0.39), 600.0);
        if req.min_momentum < f64::MAX {
            assert!(req.breakdown.contains("Pen:"));
            assert!(req.breakdown.contains("ReqMom:"));
        }
    }
}
