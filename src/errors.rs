//! errors.rs — Domain-specific typed error hierarchy for every subsystem.
//!
//! Design constraints
//! ──────────────────
//! • `thiserror` derive macros produce `std::error::Error` impls with zero
//!   runtime overhead — no vtable allocation, no boxing on the hot path.
//! • `anyhow::Error` is ONLY used at I/O boundary layers (startup, config).
//!   It is NEVER used inside the WebSocket on_message loop or evaluate_trade.
//! • Each subsystem gets its own error type so callers can match precisely
//!   without catching overly-broad `Box<dyn Error>`.
//! • All variants carry enough context to log a useful diagnostic without
//!   needing a backtrace (which would allocate on the heap mid-loop).

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Top-level bot error — routes into one of the subsystem errors below.
// Used in main() and the top-level task supervisors.
// ─────────────────────────────────────────────────────────────────────────────

/// The catch-all error type returned from `main` and top-level task spawners.
#[derive(Debug, Error)]
pub enum BotError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("WebSocket error: {0}")]
    WebSocket(#[from] WsError),

    #[error("Market fetcher error: {0}")]
    MarketFetcher(#[from] MarketFetcherError),

    #[error("Executor error: {0}")]
    Executor(#[from] ExecutorError),

    #[error("State error: {0}")]
    State(#[from] StateError),

    #[error("Signing error: {0}")]
    Signing(#[from] SigningError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigError — `.env` parsing and environment variable validation.
// These only occur at startup, never on the hot path.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    /// A required environment variable was missing entirely.
    #[error("Missing required environment variable: `{key}`")]
    MissingVar { key: &'static str },

    /// A variable was present but could not be parsed into the expected type.
    #[error("Invalid value for `{key}`: expected {expected}, got `{got}`")]
    InvalidValue {
        key: &'static str,
        expected: &'static str,
        got: String,
    },

    /// The `.env` file could not be loaded (non-fatal — we fall back to OS env).
    #[error("Failed to load .env file: {source}")]
    DotEnv {
        #[from]
        source: dotenvy::Error,
    },

    /// A numeric config value is outside the acceptable trading range.
    #[error("Config value `{key}` = {value} is out of safe range [{min}, {max}]")]
    OutOfRange {
        key: &'static str,
        value: f64,
        min: f64,
        max: f64,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// WsError — WebSocket connection and message parsing errors.
// Two separate streams (Binance, Polymarket) share this type.
// ─────────────────────────────────────────────────────────────────────────────

/// Which exchange the WebSocket error originated from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOrigin {
    Binance,
    Polymarket,
}

impl std::fmt::Display for WsOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsOrigin::Binance => f.write_str("Binance"),
            WsOrigin::Polymarket => f.write_str("Polymarket"),
        }
    }
}

#[derive(Debug, Error)]
pub enum WsError {
    /// The underlying tungstenite/tokio-tungstenite transport failed.
    #[error("[{origin}] WebSocket transport error: {source}")]
    Transport {
        origin: WsOrigin,
        #[source]
        source: tokio_tungstenite::tungstenite::Error,
    },

    /// The connection was cleanly closed by the remote end.
    #[error("[{origin}] WebSocket closed by remote: code={code:?}, reason={reason:?}")]
    Closed {
        origin: WsOrigin,
        code: Option<u16>,
        reason: Option<String>,
    },

    /// A received message could not be parsed as UTF-8 text.
    #[error("[{origin}] Non-UTF-8 binary frame received ({bytes} bytes)")]
    BinaryFrame { origin: WsOrigin, bytes: usize },

    /// `serde_json` failed to deserialise the incoming message payload.
    #[error("[{origin}] JSON parse error on message `{snippet}`: {source}")]
    JsonParse {
        origin: WsOrigin,
        snippet: String, // First 120 chars of the offending message
        #[source]
        source: serde_json::Error,
    },

    /// A required field was absent from an otherwise valid JSON message.
    #[error("[{origin}] Missing field `{field}` in message")]
    MissingField { origin: WsOrigin, field: &'static str },

    /// The subscription handshake message could not be sent.
    #[error("[{origin}] Failed to send subscription message: {source}")]
    SubscriptionFailed {
        origin: WsOrigin,
        #[source]
        source: tokio_tungstenite::tungstenite::Error,
    },

    /// Could not construct a valid URL from the configured string.
    #[error("[{origin}] Invalid WebSocket URL `{url}`: {source}")]
    InvalidUrl {
        origin: WsOrigin,
        url: String,
        #[source]
        source: url::ParseError,
    },

    /// The stream was deliberately stopped via the stop-event signal.
    #[error("[{origin}] Stream stopped by operator signal")]
    Stopped { origin: WsOrigin },
}

// ─────────────────────────────────────────────────────────────────────────────
// MarketFetcherError — Gamma API / market resolution errors.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MarketFetcherError {
    /// The HTTP request to the Gamma API failed.
    #[error("Gamma API HTTP error: {source}")]
    Http {
        #[from]
        source: reqwest::Error,
    },

    /// The API returned a non-2xx status code.
    #[error("Gamma API returned status {status} for slug `{slug}`")]
    ApiStatus { status: u16, slug: String },

    /// The JSON response body could not be deserialised.
    #[error("Failed to deserialise Gamma API response: {source}")]
    Deserialise {
        #[source]
        source: serde_json::Error,
    },

    /// No market was found for either the primary or fallback slug.
    #[error("No active market found for timestamp window {window_ts} (tried slugs: {slugs:?})")]
    NotFound { window_ts: u64, slugs: Vec<String> },

    /// The market was found but `clobTokenIds` could not be extracted.
    #[error("Could not extract token IDs from market `{market_id}`: {reason}")]
    TokenIdExtraction { market_id: String, reason: String },

    /// The `clobTokenIds` JSON string embedded in the event could not be parsed.
    #[error("Failed to parse clobTokenIds JSON for market `{market_id}`: {source}")]
    TokenIdJson {
        market_id: String,
        #[source]
        source: serde_json::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecutorError — CLOB order submission, sizing, and position tracking.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ExecutorError {
    /// The executor was called before authentication completed.
    #[error("CLOB executor is not authenticated — order aborted")]
    NotAuthenticated,

    /// The L2 API key derivation failed.
    #[error("L2 API credential derivation failed: {reason}")]
    AuthFailed { reason: String },

    /// The HTTP order POST returned an explicit error message from the CLOB.
    #[error("CLOB rejected order for token `{token_id}`: {error_msg}")]
    OrderRejected { token_id: String, error_msg: String },

    /// The reqwest HTTP layer failed (network, timeout, TLS).
    #[error("HTTP transport error during order submission: {source}")]
    Http {
        #[from]
        source: reqwest::Error,
    },

    /// Buy size resolved to zero shares (bankroll exhausted or price too high).
    #[error("Bankroll too low: ${bankroll:.2} is insufficient to buy 1 share at ${price:.4}")]
    InsufficientBankroll { bankroll: f64, price: f64 },

    /// The computed order value is below Polymarket's $1 minimum.
    #[error("Order value ${value:.2} is below the $1.00 Polymarket minimum")]
    BelowMinimum { value: f64 },

    /// No ask price was available on either the primary or synthetic book.
    #[error("No ask price (real or synthetic) available for token `{token_id}` — aborting blind fire")]
    NoAskPrice { token_id: String },

    /// The bid-ask spread exceeded the configured safety gate.
    #[error("Spread ${spread:.4} exceeds max ${max_spread:.4} for token `{token_id}` — market too thin")]
    SpreadTooWide {
        token_id: String,
        spread: f64,
        max_spread: f64,
    },

    /// The computed price is outside the valid [0.01, 0.99] CLOB price range.
    #[error("Price ${price:.4} is outside the valid CLOB range [0.01, 0.99]")]
    InvalidPrice { price: f64 },

    /// The order size (shares) is below the configured dust threshold.
    #[error("Order size {size} shares is below the dust threshold ({min_size}) — aborting")]
    DustOrder { size: u64, min_size: u64 },

    /// A response field was missing from the CLOB's success response.
    #[error("CLOB success response missing field `{field}` for token `{token_id}`")]
    MalformedResponse { token_id: String, field: &'static str },

    /// On-chain USDC balance fetch via Web3 RPC failed.
    #[error("On-chain balance fetch failed for address `{address}`: {reason}")]
    BalanceFetch { address: String, reason: String },

    /// ERC-1155 token balance fetch failed.
    #[error("ERC-1155 balance fetch failed for token `{token_id}`: {reason}")]
    TokenBalanceFetch { token_id: String, reason: String },

    /// The auto-redeemer subprocess exited with a non-zero status.
    #[error("Auto-redemption script failed for condition `{condition_id}`: {stderr}")]
    RedemptionFailed {
        condition_id: String,
        stderr: String,
    },

    /// JSON serialization error when building the order request body.
    #[error("Failed to serialize order payload: {source}")]
    Serialise {
        #[source]
        source: serde_json::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// StateError — shared state read/write guards and rollover logic.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StateError {
    /// A rollover was triggered while one was already in progress.
    #[error("Rollover already in progress — duplicate trigger suppressed")]
    RolloverAlreadyInProgress,

    /// The shared market state could not be read because the RwLock was poisoned.
    /// (Should be unreachable with `parking_lot` since it never poisons, but kept
    /// for completeness if we ever switch back to `std::sync`.)
    #[error("Market state RwLock was poisoned — internal consistency violation")]
    LockPoisoned,

    /// The sniper brain attempted to fire while the sniper is not armed.
    #[error("Trade evaluation called while sniper is disarmed")]
    NotArmed,

    /// A required token ID was missing from the shared state at trigger time.
    #[error("Token ID for direction `{direction}` is not set in market state")]
    MissingTokenId { direction: &'static str },
}

// ─────────────────────────────────────────────────────────────────────────────
// SigningError — EIP-712 / Polymarket L2 API key signing.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SigningError {
    /// The private key hex string could not be decoded.
    #[error("Invalid private key hex encoding: {source}")]
    HexDecode {
        #[from]
        source: hex::FromHexError,
    },

    /// The decoded bytes are not a valid secp256k1 scalar.
    #[error("Invalid secp256k1 private key: {reason}")]
    InvalidKey { reason: String },

    /// ECDSA signing of the order digest failed.
    #[error("ECDSA signing failed: {reason}")]
    EcdsaFailed { reason: String },

    /// The EIP-712 domain separator or struct hash could not be built.
    #[error("EIP-712 payload construction failed: {reason}")]
    Eip712Failed { reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience type aliases
// ─────────────────────────────────────────────────────────────────────────────

/// Short alias used throughout the bot's non-hot-path functions.
pub type BotResult<T> = Result<T, BotError>;

/// Used inside WebSocket tasks; avoids boxing on reconnect paths.
pub type WsResult<T> = Result<T, WsError>;

/// Used in the executor and position manager.
pub type ExecResult<T> = Result<T, ExecutorError>;

/// Used in the market fetcher.
pub type FetchResult<T> = Result<T, MarketFetcherError>;
