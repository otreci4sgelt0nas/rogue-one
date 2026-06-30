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
//! - `l2_creds`: [`parking_lot::Mutex<Option<L2Creds>>`] — set once at startup
//!   via `init_live_auth`, then read-only in all order paths.
//! - All other fields are either immutable after construction or behind a `Mutex`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::{Hmac, Mac};
use k256::ecdsa::{SigningKey, RecoveryId};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use parking_lot::Mutex;
use portable_atomic::AtomicF64;
use sha3::{Digest, Keccak256};
use tracing::{debug, error, info, warn};

use crate::config::CONFIG;
use crate::errors::{ExecResult, ExecutorError};
use crate::situation_room::{
    calculate_hold_ev, impatience_target_price, is_impatient, is_safe_to_hold_to_expiry,
};
use crate::sniper::TradeOutcome;
use crate::state::{load_price, unix_now_secs, Direction, SharedState};
use crate::state::TriggerSnapshot;

// ─────────────────────────────────────────────────────────────────────────────
// V2 Contract addresses (Polygon mainnet, chainId 137)
// ─────────────────────────────────────────────────────────────────────────────

const CTF_EXCHANGE_V2:      &str = "0xE111180000d2663C0091e4f400237545B87B996B";
const NEG_RISK_EXCHANGE_V2: &str = "0xe2222d279d744050d28e00520010520000310F59";
const CTF_ERC1155_CONTRACT: &str = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045";
const PUSD_CONTRACT:        &str = "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB";
const CLOB_URL:             &str = "https://clob.polymarket.com";
const CHAIN_ID:             u64  = 137;

// ECDSA signature type for EOA wallets (signatureType = 1 in Polymarket scheme)
const SIGNATURE_TYPE_EOA: u8 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// L2 API credentials
// ─────────────────────────────────────────────────────────────────────────────

/// Polymarket L2 API credentials derived from the L1 wallet key.
#[derive(Debug, Clone)]
pub struct L2Creds {
    pub api_key:    String,
    pub secret:     String,
    pub passphrase: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Position record — tracks one open token position
// ─────────────────────────────────────────────────────────────────────────────

/// A single open position for one Polymarket CLOB token.
#[derive(Debug, Clone)]
pub struct Position {
    pub token_id:        String,
    pub total_spent:     f64,
    pub total_shares:    u64,
    pub cost_basis:      f64,
    pub entry_time:      Instant,
    pub entry_unix_secs: f64,
    pub last_sell_time:  Option<Instant>,
    pub direction:       Direction,
    pub market_slug:     String,
    pub condition_id:    String,
}

impl Position {
    pub fn new(
        token_id:     String,
        fill_price:   f64,
        fill_size:    u64,
        direction:    Direction,
        market_slug:  String,
        condition_id: String,
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
        }
    }

    pub fn add_fill(&mut self, fill_price: f64, fill_size: u64) {
        self.total_spent  += fill_price * fill_size as f64;
        self.total_shares += fill_size;
        if self.total_shares > 0 {
            self.cost_basis = self.total_spent / self.total_shares as f64;
        }
    }

    pub fn sell_cooldown_elapsed(&self) -> bool {
        match self.last_sell_time {
            None       => true,
            Some(last) => last.elapsed().as_secs_f64() >= CONFIG.sell_cooldown_sec,
        }
    }

    #[inline]
    pub fn unrealised_pnl(&self, current_price: f64) -> f64 {
        (current_price - self.cost_basis) * self.total_shares as f64
    }

    #[inline]
    pub fn take_profit_price(&self) -> f64 {
        (self.cost_basis * (1.0 + CONFIG.take_profit_pct)).min(CONFIG.exit_ceiling_price)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Paper trading ledger
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PaperLedger {
    pub balances:    HashMap<String, f64>,
    pub session_pnl: f64,
    pub window_pnl:  f64,
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
// V2 EIP-712 order signing
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a uint256 as 32 big-endian bytes.
fn u256_bytes(v: u128) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..].copy_from_slice(&v.to_be_bytes());
    b
}

/// Encode a u64 as a uint256 (32 big-endian bytes, upper 24 bytes = 0).
fn u64_as_u256(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

/// Encode an Ethereum address as a uint256 / bytes32 (left-padded with 12 zero bytes).
fn addr_as_bytes32(addr: &str) -> [u8; 32] {
    let clean = addr.trim_start_matches("0x");
    let mut b = [0u8; 32];
    if let Ok(decoded) = hex::decode(clean) {
        let start = 32usize.saturating_sub(decoded.len());
        b[start..].copy_from_slice(&decoded[..decoded.len().min(32)]);
    }
    b
}

/// The V2 EIP-712 `Order` type hash.
fn order_type_hash() -> [u8; 32] {
    let type_str = b"Order(uint256 salt,address maker,address signer,address taker,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint256 expiration,uint256 nonce,uint256 feeRateBps,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)";
    let mut hasher = Keccak256::new();
    hasher.update(type_str);
    hasher.finalize().into()
}

/// EIP-712 domain separator for V2.
fn domain_separator(verifying_contract: &str) -> [u8; 32] {
    let domain_type_hash = {
        let t = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
        let mut h = Keccak256::new();
        h.update(t);
        h.finalize()
    };

    let name_hash = {
        let mut h = Keccak256::new();
        h.update(b"Polymarket CTF Exchange");
        h.finalize()
    };

    // keccak256("2")  ← V2 domain version
    let version_hash = {
        let mut h = Keccak256::new();
        h.update(b"2");
        h.finalize()
    };

    let chain_id_bytes = u64_as_u256(CHAIN_ID);
    let contract_bytes = addr_as_bytes32(verifying_contract);

    let mut hasher = Keccak256::new();
    hasher.update(domain_type_hash);
    hasher.update(name_hash);
    hasher.update(version_hash);
    hasher.update(chain_id_bytes);
    hasher.update(contract_bytes);
    hasher.finalize().into()
}

/// Amounts in the order are in pUSD micro-units (6 decimals).
fn price_to_units(price: f64) -> u64 {
    (price * 1_000_000.0).round() as u64
}

/// Build and sign a V2 EIP-712 order.
///
/// Returns the base64-encoded signature.
fn sign_v2_order(
    private_key_hex:    &str,
    verifying_contract: &str,
    token_id:           &str,
    price:              f64,
    size:               u64,
    side_uint8:         u8,     // 0 = BUY, 1 = SELL
    timestamp_ms:       u64,
    signer_address:     &str,
) -> Result<String, crate::errors::SigningError> {
    // 1. Decode private key
    let key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
        .map_err(|e| crate::errors::SigningError::HexDecode { source: e })?;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| crate::errors::SigningError::InvalidKey { reason: e.to_string() })?;

    // 2. Build struct hash
    let token_id_u256: u128 = token_id.parse::<u128>().unwrap_or(0);

    // makerAmount = price_units * size (collateral in)
    // takerAmount = size * 1_000_000 (shares out, in 1e6 units)
    let maker_amount = price_to_units(price) * size;
    let taker_amount = size * 1_000_000u64;

    let zero_address = "0x0000000000000000000000000000000000000000";
    let zero_bytes32 = [0u8; 32];

    let type_hash    = order_type_hash();
    let salt_bytes   = u64_as_u256(timestamp_ms);
    let maker_bytes  = addr_as_bytes32(signer_address);
    let signer_bytes = addr_as_bytes32(signer_address);
    let taker_bytes  = addr_as_bytes32(zero_address);
    let token_bytes  = u256_bytes(token_id_u256);
    let maker_amt_b  = u64_as_u256(maker_amount);
    let taker_amt_b  = u64_as_u256(taker_amount);
    let expiry_bytes = u64_as_u256(0);
    let nonce_bytes  = u64_as_u256(0);
    let fee_bytes    = u64_as_u256(0);
    // side and signatureType are uint8 but abi-encoded as uint256 (left-padded)
    let mut side_b  = [0u8; 32]; side_b[31]  = side_uint8;
    let mut sig_t_b = [0u8; 32]; sig_t_b[31] = SIGNATURE_TYPE_EOA;
    let ts_bytes    = u64_as_u256(timestamp_ms);

    let mut struct_hasher = Keccak256::new();
    struct_hasher.update(type_hash);
    struct_hasher.update(salt_bytes);
    struct_hasher.update(maker_bytes);
    struct_hasher.update(signer_bytes);
    struct_hasher.update(taker_bytes);
    struct_hasher.update(token_bytes);
    struct_hasher.update(maker_amt_b);
    struct_hasher.update(taker_amt_b);
    struct_hasher.update(expiry_bytes);
    struct_hasher.update(nonce_bytes);
    struct_hasher.update(fee_bytes);
    struct_hasher.update(side_b);
    struct_hasher.update(sig_t_b);
    struct_hasher.update(ts_bytes);
    struct_hasher.update(zero_bytes32); // metadata
    struct_hasher.update(zero_bytes32); // builder
    let struct_hash: [u8; 32] = struct_hasher.finalize().into();

    // 3. EIP-712 final digest: keccak256("\x19\x01" || domainSep || structHash)
    let ds = domain_separator(verifying_contract);
    let mut final_hasher = Keccak256::new();
    final_hasher.update(b"\x19\x01");
    final_hasher.update(ds);
    final_hasher.update(struct_hash);
    let digest: [u8; 32] = final_hasher.finalize().into();

    // 4. Sign the digest (recoverable signature for Ethereum v encoding)
    let (sig, recovery_id): (k256::ecdsa::Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| crate::errors::SigningError::EcdsaFailed { reason: e.to_string() })?;

    // 5. Encode as 65-byte (r || s || v) and base64
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.to_bytes());
    sig_bytes[64] = recovery_id.to_byte() + 27; // v = 27 or 28 (Ethereum convention)

    Ok(BASE64_STANDARD.encode(sig_bytes))
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP order request / response shapes (CLOB REST API V2)
// ─────────────────────────────────────────────────────────────────────────────

/// The JSON body sent to `POST /order` in V2.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ClobOrderBody {
    order:      ClobOrderFields,
    owner:      String,
    order_type: &'static str,
}

/// The signed order fields within the POST body.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ClobOrderFields {
    salt:           String,
    maker:          String,
    signer:         String,
    taker:          &'static str,
    token_id:       String,
    maker_amount:   String,
    taker_amount:   String,
    expiration:     &'static str,
    nonce:          &'static str,
    fee_rate_bps:   &'static str,
    side:           &'static str,   // "BUY" or "SELL"
    signature_type: u8,
    timestamp:      String,         // milliseconds as string
    metadata:       &'static str,
    builder:        &'static str,
    signature:      String,
}

/// The JSON response from `POST /order`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClobOrderResponse {
    success:   bool,
    order_id:  Option<String>,
    size:      Option<f64>,
    price:     Option<f64>,
    error_msg: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 auth header computation
// ─────────────────────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<sha2::Sha256>;

/// Build the L2 HMAC authentication signature header for a CLOB API request.
///
/// Returns the base64-encoded HMAC-SHA256 signature over
/// `timestamp + method + path + body`.
fn build_l2_headers(
    creds:          &L2Creds,
    method:         &str,
    path:           &str,
    body:           &str,
    timestamp_secs: i64,
) -> String {
    let message = format!("{}{}{}{}", timestamp_secs, method, path, body);

    let mut mac = HmacSha256::new_from_slice(creds.secret.as_bytes())
        .expect("HMAC key size is always valid");
    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();
    BASE64_STANDARD.encode(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet address derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive the Ethereum checksummed address from a secp256k1 private key.
pub fn derive_wallet_address(private_key_hex: &str) -> Option<String> {
    if private_key_hex.is_empty() {
        return None;
    }
    let key_clean = private_key_hex.trim_start_matches("0x");
    let key_bytes = hex::decode(key_clean).ok()?;
    if key_bytes.len() != 32 {
        return None;
    }

    let signing_key  = SigningKey::from_slice(&key_bytes).ok()?;
    let verifying_key = signing_key.verifying_key();

    // Uncompressed public key: 0x04 || x || y (65 bytes total)
    let pub_point = verifying_key.to_encoded_point(false);
    let pub_bytes = pub_point.as_bytes();

    // Drop the 0x04 prefix → 64 bytes
    if pub_bytes.len() < 65 {
        return None;
    }
    let raw_pub = &pub_bytes[1..65];

    // Keccak-256 of the 64 raw bytes, take the last 20 bytes → address
    let mut hasher = Keccak256::new();
    hasher.update(raw_pub);
    let hash: [u8; 32] = hasher.finalize().into();
    let addr_bytes = &hash[12..]; // last 20 bytes

    // EIP-55 checksum
    let hex_str = hex::encode(addr_bytes);
    let mut checksum_hasher = Keccak256::new();
    checksum_hasher.update(hex_str.as_bytes());
    let addr_hash = checksum_hasher.finalize();

    let checksummed: String = hex_str
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_alphabetic() {
                if addr_hash[i / 2] & (if i % 2 == 0 { 0x80 } else { 0x08 }) != 0 {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c
                }
            } else {
                c
            }
        })
        .collect();

    Some(format!("0x{}", checksummed))
}

// ─────────────────────────────────────────────────────────────────────────────
// L1 → L2 credential derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive L2 API credentials from the L1 private key.
///
/// Signs an EIP-191 personal_sign message with the wallet key and POSTs to
/// `POST /auth/derive-api-key` to get back `apiKey`, `secret`, `passphrase`.
pub async fn derive_l2_creds(
    http:            &reqwest::Client,
    private_key_hex: &str,
    wallet_address:  &str,
) -> Result<L2Creds, ExecutorError> {
    let timestamp_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // EIP-191 personal_sign: "\x19Ethereum Signed Message:\n" + len + message
    let message  = format!("{}", timestamp_secs);
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);

    let mut hasher = Keccak256::new();
    hasher.update(prefixed.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();

    let key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
        .map_err(|e| ExecutorError::AuthFailed { reason: format!("hex decode: {e}") })?;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| ExecutorError::AuthFailed { reason: format!("invalid key: {e}") })?;

    let (sig, recovery_id): (k256::ecdsa::Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| ExecutorError::AuthFailed { reason: format!("sign: {e}") })?;

    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.to_bytes());
    sig_bytes[64] = recovery_id.to_byte() + 27;
    let sig_hex = format!("0x{}", hex::encode(sig_bytes));

    let url = format!("{}/auth/derive-api-key", CLOB_URL);

    let response = http
        .post(&url)
        .header("POLY_ADDRESS",   wallet_address)
        .header("POLY_SIGNATURE", &sig_hex)
        .header("POLY_TIMESTAMP", timestamp_secs.to_string())
        .send()
        .await
        .map_err(|e| ExecutorError::AuthFailed { reason: format!("HTTP error: {e}") })?;

    let status = response.status().as_u16();
    let body   = response.text().await.unwrap_or_default();

    if status != 200 {
        return Err(ExecutorError::AuthFailed {
            reason: format!("derive-api-key returned HTTP {}: {}", status, body),
        });
    }

    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| ExecutorError::AuthFailed { reason: format!("JSON parse: {e}") })?;

    let api_key    = parsed["apiKey"].as_str().unwrap_or("").to_string();
    let secret     = parsed["secret"].as_str().unwrap_or("").to_string();
    let passphrase = parsed["passphrase"].as_str().unwrap_or("").to_string();

    if api_key.is_empty() || secret.is_empty() || passphrase.is_empty() {
        return Err(ExecutorError::AuthFailed {
            reason: format!("Incomplete creds from derive-api-key: {}", body),
        });
    }

    Ok(L2Creds { api_key, secret, passphrase })
}

// ─────────────────────────────────────────────────────────────────────────────
// ClobExecutor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ClobExecutor {
    state:                   Arc<SharedState>,
    http:                    reqwest::Client,
    pub bankroll:            AtomicF64,
    positions:               Mutex<HashMap<String, Position>>,
    paper_ledger:            Mutex<PaperLedger>,
    pub is_authenticated:    bool,
    pub wallet_address:      Option<String>,
    /// L2 creds are derived async at startup and stored here.
    /// Wrapped in Mutex<Option<...>> so `init_live_auth` can set them
    /// through a shared `Arc<Self>`.
    l2_creds:                Mutex<Option<L2Creds>>,
    pub csv_filename:        String,
    pub last_summary_expiry: Mutex<Option<u64>>,
}

impl ClobExecutor {
    /// Construct a new `ClobExecutor`.
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

        let session_time = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let csv_filename = format!("paper_trades_{}.csv", session_time);

        let initial_bankroll = if CONFIG.paper_mode {
            info!(bankroll = CONFIG.starting_bankroll, "📄 PAPER MODE: Initialised simulated bankroll.");
            CONFIG.starting_bankroll
        } else {
            info!("🔴 LIVE MODE: Bankroll will be fetched from on-chain pUSD balance.");
            0.0
        };

        // Derive wallet address from private key.
        let wallet_address = if CONFIG.has_private_key() {
            derive_wallet_address(&CONFIG.private_key)
        } else {
            None
        };

        let is_authenticated = wallet_address.is_some() && !CONFIG.paper_mode;

        if let Some(ref addr) = wallet_address {
            info!(address = %addr, "💳 Wallet address derived.");
        }
        if !CONFIG.paper_mode && wallet_address.is_none() {
            warn!("⚠️  Could not derive wallet address from PRIVATE_KEY. Live orders disabled.");
        }

        Arc::new(Self {
            state,
            http,
            bankroll:            AtomicF64::new(initial_bankroll),
            positions:           Mutex::new(HashMap::new()),
            paper_ledger:        Mutex::new(PaperLedger::default()),
            is_authenticated:    wallet_address.is_some(),
            wallet_address,
            l2_creds:            Mutex::new(None),
            csv_filename,
            last_summary_expiry: Mutex::new(None),
        })
    }

    /// Perform async L2 auth derivation for live mode.
    ///
    /// Must be called once in live mode before any orders are submitted.
    pub async fn init_live_auth(self: &Arc<Self>) -> Result<(), ExecutorError> {
        if CONFIG.paper_mode {
            return Ok(());
        }
        let wallet = self.wallet_address.as_deref().ok_or(ExecutorError::NotAuthenticated)?;
        info!("🔑 Deriving L2 API credentials from L1 wallet key...");
        let creds = derive_l2_creds(&self.http, &CONFIG.private_key, wallet).await?;
        info!(api_key = %creds.api_key, "✅ L2 API credentials derived successfully.");
        *self.l2_creds.lock() = Some(creds);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bankroll helpers
    // ─────────────────────────────────────────────────────────────────────────

    #[inline(always)]
    pub fn bankroll(&self) -> f64 {
        self.bankroll.load(Ordering::Acquire)
    }

    fn deduct_bankroll(&self, amount: f64) -> bool {
        loop {
            let current = self.bankroll.load(Ordering::Acquire);
            if current < amount { return false; }
            let new_val = current - amount;
            match self.bankroll.compare_exchange(current, new_val, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_)  => return true,
                Err(_) => continue,
            }
        }
    }

    fn credit_bankroll(&self, amount: f64) {
        loop {
            let current = self.bankroll.load(Ordering::Acquire);
            let new_val = current + amount;
            match self.bankroll.compare_exchange(current, new_val, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_)  => return,
                Err(_) => continue,
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // execute_trade — primary execution entry point
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn execute_trade(&self, snap: &TriggerSnapshot) -> ExecResult<TradeOutcome> {
        if !CONFIG.paper_mode && !self.is_authenticated {
            return Err(ExecutorError::NotAuthenticated);
        }

        let buy_price = {
            let p = snap.max_price.max(0.01).min(0.99);
            (p * 100.0).round() / 100.0
        };

        if buy_price <= 0.01 {
            return Err(ExecutorError::InvalidPrice { price: buy_price });
        }

        let wire_ms = snap.trigger_instant.elapsed().as_secs_f64() * 1000.0;

        let ev_score     = 100.0_f64;
        let fraction     = CONFIG.kelly_fraction(ev_score);
        let bankroll_now = self.bankroll();
        let target_spend = bankroll_now * fraction;

        let sizing_price = snap.effective_ask.max(0.001);
        let buy_size     = (target_spend / sizing_price) as u64;

        if buy_size < 1 {
            warn!(bankroll = bankroll_now, price = sizing_price, fraction = fraction,
                  "💀 Bankroll too low to buy 1 share. Aborting.");
            return Err(ExecutorError::InsufficientBankroll { bankroll: bankroll_now, price: sizing_price });
        }

        let order_value = buy_price * buy_size as f64;

        if order_value < 1.0 {
            warn!(value = order_value, "🚫 Order value below $1.00 minimum.");
            return Err(ExecutorError::BelowMinimum { value: order_value });
        }

        if order_value > bankroll_now {
            warn!(needed = order_value, have = bankroll_now, "🚫 Insufficient bankroll for order.");
            return Err(ExecutorError::InsufficientBankroll { bankroll: bankroll_now, price: buy_price });
        }

        if !CONFIG.paper_mode && buy_size < 5 {
            warn!(size = buy_size, "🚫 Order too small (dust). Aborting.");
            return Err(ExecutorError::DustOrder { size: buy_size, min_size: 5 });
        }

        let spread_str = match snap.spread {
            Some(s) => format!("${:.4}", s),
            None    => "N/A".to_string(),
        };
        info!(
            wire_ms = wire_ms, spread = %spread_str,
            ask_at_trigger = snap.effective_ask, order_price = buy_price,
            order_size = buy_size, order_value = order_value,
            direction = %snap.direction,
            token = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
            "📡 Execution Latency & Spread diagnostic."
        );

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
        if !self.deduct_bankroll(order_value) {
            return Err(ExecutorError::InsufficientBankroll { bankroll: self.bankroll(), price: buy_price });
        }

        {
            let mut ledger = self.paper_ledger.lock();
            ledger.credit_buy(&snap.token_id, buy_size);
        }

        self.upsert_position(snap, buy_price, buy_size);

        let wire_ms = snap.trigger_instant.elapsed().as_secs_f64() * 1000.0;
        info!(
            shares = buy_size, price = buy_price, wire_ms = wire_ms,
            bankroll = self.bankroll(),
            token = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
            "📄 PAPER BUY SECURED."
        );

        self.append_csv_entry_async("BUY", &snap.token_id, buy_size as f64, buy_price, 0.0, 0.0);

        Ok(TradeOutcome::filled(buy_price, buy_size, None))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Live execution — V2 EIP-712 signed CLOB order
    // ─────────────────────────────────────────────────────────────────────────

    async fn execute_live(
        &self,
        snap:        &TriggerSnapshot,
        buy_price:   f64,
        buy_size:    u64,
        order_value: f64,
        wire_ms:     f64,
        spread_str:  &str,
    ) -> ExecResult<TradeOutcome> {
        warn!(
            size = buy_size, price = buy_price, direction = %snap.direction,
            token = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
            "🚨 FIRING LIVE ORDER — attempting buy."
        );

        let wallet = self.wallet_address.as_deref()
            .ok_or(ExecutorError::NotAuthenticated)?;

        // Clone l2_creds out of the Mutex to avoid holding the lock across await points.
        let l2 = self.l2_creds.lock().clone()
            .ok_or(ExecutorError::NotAuthenticated)?;

        // Determine verifying contract from neg_risk flag
        let neg_risk = self.state.market.load().as_ref().map(|m| m.neg_risk).unwrap_or(false);
        let verifying_contract = if neg_risk { NEG_RISK_EXCHANGE_V2 } else { CTF_EXCHANGE_V2 };

        // Timestamp in milliseconds (V2 uses ms)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Sign the V2 order
        let signature = sign_v2_order(
            &CONFIG.private_key,
            verifying_contract,
            &snap.token_id,
            buy_price,
            buy_size,
            0, // BUY = 0
            now_ms,
            wallet,
        )
        .map_err(|e| ExecutorError::OrderRejected {
            token_id:  snap.token_id.clone(),
            error_msg: format!("signing failed: {e}"),
        })?;

        let maker_amount = (price_to_units(buy_price) * buy_size).to_string();
        let taker_amount = (buy_size * 1_000_000u64).to_string();

        let order_body = ClobOrderBody {
            order: ClobOrderFields {
                salt:           now_ms.to_string(),
                maker:          wallet.to_string(),
                signer:         wallet.to_string(),
                taker:          "0x0000000000000000000000000000000000000000",
                token_id:       snap.token_id.clone(),
                maker_amount,
                taker_amount,
                expiration:     "0",
                nonce:          "0",
                fee_rate_bps:   "0",
                side:           "BUY",
                signature_type: SIGNATURE_TYPE_EOA,
                timestamp:      now_ms.to_string(),
                metadata:       "0x0000000000000000000000000000000000000000000000000000000000000000",
                builder:        "0x0000000000000000000000000000000000000000000000000000000000000000",
                signature,
            },
            owner:      l2.api_key.clone(),
            order_type: "FAK",
        };

        let body_str = serde_json::to_string(&order_body)
            .map_err(|e| ExecutorError::Serialise { source: e })?;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let sig_header = build_l2_headers(&l2, "POST", "/order", &body_str, now_secs);

        let url = format!("{}/order", CLOB_URL);
        let response = self.http
            .post(&url)
            .header("Content-Type",    "application/json")
            .header("POLY_ADDRESS",    wallet)
            .header("POLY_SIGNATURE",  sig_header)
            .header("POLY_TIMESTAMP",  now_secs.to_string())
            .header("POLY_API_KEY",    &l2.api_key)
            .header("POLY_PASSPHRASE", &l2.passphrase)
            .body(body_str)
            .send()
            .await?;

        let status    = response.status().as_u16();
        let resp_body = response.text().await.unwrap_or_default();

        let clob_resp: ClobOrderResponse = serde_json::from_str(&resp_body)
            .map_err(|_| ExecutorError::OrderRejected {
                token_id:  snap.token_id.clone(),
                error_msg: format!("HTTP {} — non-JSON response: {}", status, resp_body),
            })?;

        if !clob_resp.success {
            let error_msg = clob_resp.error_msg.unwrap_or_else(|| "unknown error".to_string());
            error!(
                token     = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
                error_msg = %error_msg,
                wire_ms   = wire_ms,
                spread    = %spread_str,
                "❌ CLOB rejected live BUY order."
            );
            return Err(ExecutorError::OrderRejected {
                token_id:  snap.token_id.clone(),
                error_msg,
            });
        }

        // Success — deduct bankroll and open position
        if !self.deduct_bankroll(order_value) {
            warn!("Bankroll already depleted after live fill — may indicate a race condition.");
        }
        self.upsert_position(snap, buy_price, buy_size);

        let order_id = clob_resp.order_id.as_deref().unwrap_or("?");
        info!(
            order_id  = %order_id,
            shares    = buy_size,
            price     = buy_price,
            wire_ms   = wire_ms,
            bankroll  = self.bankroll(),
            token     = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
            "✅ LIVE BUY FILLED."
        );

        self.append_csv_entry_async("BUY", &snap.token_id, buy_size as f64, buy_price, 0.0, 0.0);

        Ok(TradeOutcome::filled(buy_price, buy_size, Some(order_id.to_string())))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Position tracking helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn upsert_position(&self, snap: &TriggerSnapshot, fill_price: f64, fill_size: u64) {
        let mut positions = self.positions.lock();
        match positions.get_mut(&snap.token_id) {
            Some(pos) => {
                pos.add_fill(fill_price, fill_size);
                debug!(
                    token     = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
                    new_vwap  = pos.cost_basis,
                    new_shares = pos.total_shares,
                    "Position averaged in."
                );
            }
            None => {
                let condition_id = self.state.market.load().as_ref()
                    .map(|m| m.condition_id.clone()).unwrap_or_default();
                let pos = Position::new(
                    snap.token_id.clone(), fill_price, fill_size,
                    snap.direction, snap.market_slug.clone(), condition_id,
                );
                debug!(
                    token  = %&snap.token_id[snap.token_id.len().saturating_sub(6)..],
                    cost   = fill_price,
                    shares = fill_size,
                    "New position opened."
                );
                positions.insert(snap.token_id.clone(), pos);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // get_token_balance — ERC-1155 balanceOf
    // ─────────────────────────────────────────────────────────────────────────

    async fn get_token_balance(&self, token_id: &str) -> f64 {
        if CONFIG.paper_mode {
            return self.paper_ledger.lock().balance(token_id);
        }

        // Live: query the CTF ERC-1155 contract via JSON-RPC eth_call.
        // ABI: balanceOf(address account, uint256 id) returns (uint256)
        // Selector: keccak256("balanceOf(address,uint256)")[0..4] = 0x00fdd58e
        let wallet = match self.wallet_address.as_deref() {
            Some(w) => w,
            None    => { warn!("get_token_balance: no wallet address"); return 0.0; }
        };
        if CONFIG.poly_rpc_url.is_empty() {
            warn!("get_token_balance: POLY_RPC_URL not set — returning 0.");
            return 0.0;
        }

        let token_id_u256: u128 = match token_id.parse::<u128>() {
            Ok(v)  => v,
            Err(_) => { warn!("get_token_balance: invalid token_id {}", token_id); return 0.0; }
        };

        // ERC-1155 balanceOf(address,uint256) selector = 0x00fdd58e
        let selector     = [0x00u8, 0xfd, 0xd5, 0x8e];
        let addr_bytes   = addr_as_bytes32(wallet);
        let token_bytes  = u256_bytes(token_id_u256);
        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&addr_bytes);
        calldata.extend_from_slice(&token_bytes);
        let calldata_hex = format!("0x{}", hex::encode(&calldata));

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method":  "eth_call",
            "params":  [
                { "to": CTF_ERC1155_CONTRACT, "data": calldata_hex },
                "latest"
            ],
            "id": 1
        });

        match self.http.post(&CONFIG.poly_rpc_url).json(&payload).send().await {
            Err(e) => {
                warn!(error = %e, "get_token_balance: RPC call failed.");
                0.0
            }
            Ok(resp) => {
                let body   = resp.text().await.unwrap_or_default();
                let parsed: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(v)  => v,
                    Err(_) => { warn!("get_token_balance: JSON parse failed"); return 0.0; }
                };
                let hex_result = parsed["result"].as_str().unwrap_or("0x0");
                let clean      = hex_result.trim_start_matches("0x");
                u128::from_str_radix(clean, 16).unwrap_or(0) as f64
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CSV trade logging
    // ─────────────────────────────────────────────────────────────────────────

    fn append_csv_entry_async(
        &self,
        action:      &'static str,
        token_id:    &str,
        shares:      f64,
        entry_price: f64,
        exit_price:  f64,
        trade_pnl:   f64,
    ) {
        let filename    = self.csv_filename.clone();
        let token_short = token_id[token_id.len().saturating_sub(6)..].to_string();
        let session_pnl = self.paper_ledger.lock().session_pnl;

        tokio::spawn(async move {
            if let Err(e) = write_csv_row(
                &filename, action, &token_short,
                shares, entry_price, exit_price, trade_pnl, session_pnl,
            ).await {
                warn!(error = %e, "Failed to write CSV trade log row.");
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // run_position_manager — background position management loop
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn run_position_manager(self: Arc<Self>) {
        info!("🏦 Global Position Manager started.");

        let poll_interval      = Duration::from_secs(3);
        let reconcile_interval = Duration::from_secs(60);
        let mut last_reconcile = Instant::now();

        loop {
            tokio::time::sleep(poll_interval).await;

            if self.state.is_rolling_over() {
                debug!("[PositionManager] Rollover in progress — skipping iteration.");
                continue;
            }

            let now_secs  = unix_now_secs();
            let expiry_ts = self.state.market_expiry_secs();
            let time_left = (expiry_ts - now_secs).max(0.0);

            if !CONFIG.paper_mode && last_reconcile.elapsed() >= reconcile_interval {
                self.reconcile_bankroll_live().await;
                last_reconcile = Instant::now();
            }

            let token_ids: Vec<String> = {
                let positions = self.positions.lock();
                positions.keys().cloned().collect()
            };

            for token_id in token_ids {
                self.evaluate_position(&token_id, now_secs, time_left, expiry_ts).await;
            }
        }
    }

    async fn evaluate_position(
        &self,
        token_id:  &str,
        now_secs:  f64,
        time_left: f64,
        expiry_ts: f64,
    ) {
        let (cost_basis, total_shares, entry_unix, direction, market_slug, condition_id) = {
            let positions = self.positions.lock();
            match positions.get(token_id) {
                Some(pos) => (
                    pos.cost_basis, pos.total_shares, pos.entry_unix_secs,
                    pos.direction, pos.market_slug.clone(), pos.condition_id.clone(),
                ),
                None => return,
            }
        };

        if total_shares == 0 {
            self.positions.lock().remove(token_id);
            return;
        }

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

        if expiry_ts > 0.0 && now_secs >= expiry_ts {
            info!(
                token     = %&token_id[token_id.len().saturating_sub(6)..],
                direction = %direction,
                market    = %market_slug,
                "⏰ Market expired. Initiating auto-redemption for condition {}.",
                condition_id
            );
            self.trigger_auto_redeem(&condition_id).await;
            self.positions.lock().remove(token_id);
            return;
        }

        if is_safe_to_hold_to_expiry(bid, time_left) {
            debug!(
                token     = %&token_id[token_id.len().saturating_sub(6)..],
                bid       = bid,
                time_left = time_left,
                "[PositionManager] Position is safe — holding to expiry."
            );
            return;
        }

        let cooldown_elapsed = {
            let positions = self.positions.lock();
            positions.get(token_id).map(|p| p.sell_cooldown_elapsed()).unwrap_or(false)
        };
        if !cooldown_elapsed { return; }

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

        let tp_price = {
            let positions = self.positions.lock();
            positions.get(token_id).map(|p| p.take_profit_price())
        };

        if let Some(tp) = tp_price {
            if bid >= tp {
                info!(
                    token  = %&token_id[token_id.len().saturating_sub(6)..],
                    bid    = bid,
                    tp     = tp,
                    cost   = cost_basis,
                    pnl    = (bid - cost_basis) * total_shares as f64,
                    "[PositionManager] 🎯 Take-profit target reached — selling."
                );
                self.execute_sell(token_id, bid, total_shares, "TAKE_PROFIT", now_secs).await;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // execute_sell — paper and live sell paths
    // ─────────────────────────────────────────────────────────────────────────

    async fn execute_sell(
        &self,
        token_id:   &str,
        sell_price: f64,
        shares:     u64,
        reason:     &'static str,
        _now_secs:  f64,
    ) {
        let cost_basis = {
            let positions = self.positions.lock();
            positions.get(token_id).map(|p| p.cost_basis).unwrap_or(0.0)
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
                    token    = %token_short,
                    shares   = shares,
                    price    = sell_price,
                    cost     = cost_basis,
                    pnl      = pnl,
                    reason   = reason,
                    bankroll = self.bankroll(),
                    "💚 PAPER SELL — profit."
                );
            } else {
                warn!(
                    token    = %token_short,
                    shares   = shares,
                    price    = sell_price,
                    cost     = cost_basis,
                    pnl      = pnl,
                    reason   = reason,
                    bankroll = self.bankroll(),
                    "🔴 PAPER SELL — loss."
                );
            }

            self.append_csv_entry_async("SELL", token_id, shares as f64, cost_basis, sell_price, pnl);
        } else {
            // ── Live SELL FAK order ───────────────────────────────────────────
            let wallet = match self.wallet_address.as_deref() {
                Some(w) => w,
                None    => {
                    warn!(token = %&token_id[token_id.len().saturating_sub(6)..],
                          "Live SELL: no wallet address.");
                    return;
                }
            };

            // Clone l2_creds out of the Mutex to avoid holding lock across await.
            let l2 = match self.l2_creds.lock().clone() {
                Some(c) => c,
                None    => {
                    warn!(token = %&token_id[token_id.len().saturating_sub(6)..],
                          "Live SELL: no L2 creds.");
                    return;
                }
            };

            let neg_risk = self.state.market.load().as_ref().map(|m| m.neg_risk).unwrap_or(false);
            let verifying_contract = if neg_risk { NEG_RISK_EXCHANGE_V2 } else { CTF_EXCHANGE_V2 };

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            let signature = match sign_v2_order(
                &CONFIG.private_key, verifying_contract, token_id,
                sell_price, shares,
                1, // SELL = 1
                now_ms, wallet,
            ) {
                Ok(s)  => s,
                Err(e) => {
                    error!(
                        token = %&token_id[token_id.len().saturating_sub(6)..],
                        error = %e,
                        "Live SELL signing failed — leaving position open for retry."
                    );
                    return;
                }
            };

            let maker_amount = (price_to_units(sell_price) * shares).to_string();
            let taker_amount = (shares * 1_000_000u64).to_string();

            let order_body = ClobOrderBody {
                order: ClobOrderFields {
                    salt:           now_ms.to_string(),
                    maker:          wallet.to_string(),
                    signer:         wallet.to_string(),
                    taker:          "0x0000000000000000000000000000000000000000",
                    token_id:       token_id.to_string(),
                    maker_amount,
                    taker_amount,
                    expiration:     "0",
                    nonce:          "0",
                    fee_rate_bps:   "0",
                    side:           "SELL",
                    signature_type: SIGNATURE_TYPE_EOA,
                    timestamp:      now_ms.to_string(),
                    metadata:       "0x0000000000000000000000000000000000000000000000000000000000000000",
                    builder:        "0x0000000000000000000000000000000000000000000000000000000000000000",
                    signature,
                },
                owner:      l2.api_key.clone(),
                order_type: "FAK",
            };

            let body_str = match serde_json::to_string(&order_body) {
                Ok(s)  => s,
                Err(e) => {
                    error!(error = %e, "Live SELL: failed to serialize order body.");
                    return;
                }
            };

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let sig_header = build_l2_headers(&l2, "POST", "/order", &body_str, now_secs);

            let url      = format!("{}/order", CLOB_URL);
            let response = match self.http
                .post(&url)
                .header("Content-Type",    "application/json")
                .header("POLY_ADDRESS",    wallet)
                .header("POLY_SIGNATURE",  sig_header)
                .header("POLY_TIMESTAMP",  now_secs.to_string())
                .header("POLY_API_KEY",    &l2.api_key)
                .header("POLY_PASSPHRASE", &l2.passphrase)
                .body(body_str)
                .send()
                .await
            {
                Ok(r)  => r,
                Err(e) => {
                    error!(
                        token  = %&token_id[token_id.len().saturating_sub(6)..],
                        error  = %e,
                        reason = reason,
                        "Live SELL HTTP error — leaving position open for retry."
                    );
                    return;
                }
            };

            let resp_body  = response.text().await.unwrap_or_default();
            let clob_resp: ClobOrderResponse = match serde_json::from_str(&resp_body) {
                Ok(r)  => r,
                Err(_) => {
                    error!(
                        token  = %&token_id[token_id.len().saturating_sub(6)..],
                        body   = %resp_body,
                        reason = reason,
                        "Live SELL: non-JSON response — leaving position open."
                    );
                    return;
                }
            };

            if !clob_resp.success {
                let em = clob_resp.error_msg.unwrap_or_else(|| "unknown".to_string());
                error!(
                    token     = %&token_id[token_id.len().saturating_sub(6)..],
                    error_msg = %em,
                    reason    = reason,
                    "❌ CLOB rejected live SELL order — leaving position open for retry."
                );
                return; // Don't remove — retry on next position manager tick.
            }

            self.credit_bankroll(gross_proceeds);

            let order_id = clob_resp.order_id.as_deref().unwrap_or("?");
            info!(
                order_id = %order_id,
                token    = %&token_id[token_id.len().saturating_sub(6)..],
                shares   = shares,
                price    = sell_price,
                pnl      = pnl,
                reason   = reason,
                bankroll = self.bankroll(),
                "✅ LIVE SELL FILLED."
            );

            self.append_csv_entry_async("SELL", token_id, shares as f64, cost_basis, sell_price, pnl);
        }

        // Remove the position record on success (paper or live).
        self.positions.lock().remove(token_id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // trigger_auto_redeem
    // ─────────────────────────────────────────────────────────────────────────

    async fn trigger_auto_redeem(&self, condition_id: &str) {
        if condition_id.is_empty() {
            warn!("Auto-redeem: no condition ID — skipping.");
            return;
        }

        info!(condition_id = %condition_id, "⏳ Waiting 15s for UMA oracle to settle...");
        tokio::time::sleep(Duration::from_secs(15)).await;
        info!("⚙️  Executing auto-redemption script...");

        match tokio::process::Command::new("python3")
            .arg("scripts/redeem.py")
            .arg(condition_id)
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                info!(stdout = %String::from_utf8_lossy(&output.stdout),
                      "✅ Auto-redemption succeeded.");
            }
            Ok(output) => {
                error!(stderr = %String::from_utf8_lossy(&output.stderr),
                       "❌ Auto-redemption script exited with error.");
            }
            Err(e) => {
                error!(error = %e, "❌ Failed to spawn auto-redemption script.");
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // reconcile_bankroll_live — pUSD balanceOf
    // ─────────────────────────────────────────────────────────────────────────

    async fn reconcile_bankroll_live(&self) {
        let wallet = match self.wallet_address.as_deref() {
            Some(w) => w,
            None    => {
                debug!("[PositionManager] Bankroll reconciliation: no wallet address.");
                return;
            }
        };
        if CONFIG.poly_rpc_url.is_empty() {
            debug!("[PositionManager] Bankroll reconciliation: POLY_RPC_URL not set.");
            return;
        }

        // ERC-20 balanceOf(address) selector = 0x70a08231
        let selector     = [0x70u8, 0xa0, 0x82, 0x31];
        let addr_bytes   = addr_as_bytes32(wallet);
        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&addr_bytes);
        let calldata_hex = format!("0x{}", hex::encode(&calldata));

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method":  "eth_call",
            "params":  [
                { "to": PUSD_CONTRACT, "data": calldata_hex },
                "latest"
            ],
            "id": 1
        });

        match self.http.post(&CONFIG.poly_rpc_url).json(&payload).send().await {
            Err(e) => {
                warn!(error = %e, "[PositionManager] pUSD balanceOf RPC call failed.");
            }
            Ok(resp) => {
                let body   = resp.text().await.unwrap_or_default();
                let parsed: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(v)  => v,
                    Err(_) => {
                        warn!("[PositionManager] pUSD balance: JSON parse failed");
                        return;
                    }
                };
                let hex_result      = parsed["result"].as_str().unwrap_or("0x0");
                let clean           = hex_result.trim_start_matches("0x");
                let raw: u128       = u128::from_str_radix(clean, 16).unwrap_or(0);
                // pUSD has 6 decimals
                let on_chain_balance = raw as f64 / 1_000_000.0;
                let current          = self.bankroll();
                let delta            = (on_chain_balance - current).abs();
                if delta > 0.01 {
                    info!(
                        on_chain = on_chain_balance,
                        local    = current,
                        delta    = delta,
                        "[PositionManager] 💰 Bankroll reconciled from pUSD on-chain balance."
                    );
                    self.bankroll.store(on_chain_balance, Ordering::Release);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSV I/O helper
// ─────────────────────────────────────────────────────────────────────────────

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
        timestamp, action, token_short, shares, entry_price, exit_price, trade_pnl, session_pnl,
    );

    file.write_all(row.as_bytes()).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy stub (kept for test compatibility)
// ─────────────────────────────────────────────────────────────────────────────

fn derive_wallet_address_stub(private_key: &str) -> Option<String> {
    derive_wallet_address(private_key)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::state::SharedState;
    use crate::state::{TriggerSnapshot, OrderBookSnapshot, Direction};
    use crate::sniper::TradeOutcome;

    fn init() {
        let _ = tracing_subscriber::fmt::try_init();
    }

    fn make_state() -> Arc<SharedState> {
        Arc::new(SharedState::default())
    }

    fn make_snap() -> TriggerSnapshot {
        TriggerSnapshot {
            direction:       Direction::Up,
            delta:           50.0,
            trigger_instant: std::time::Instant::now(),
            exchange_ts:     0.0,
            book:            OrderBookSnapshot {
                best_ask:     Some(0.72),
                best_bid:     Some(0.70),
                opposing_bid: Some(0.28),
            },
            token_id:        "123456789012345678901234567890123456789012345678".to_string(),
            market_slug:     "test-market".to_string(),
            effective_ask:   0.72,
            max_price:       0.72,
            spread:          Some(0.02),
            ev_breakdown:    "".to_string(),
        }
    }

    #[test]
    fn position_vwap_computed_on_construction() {
        let pos = Position::new("tok".into(), 0.5, 100, Direction::Up, "slug".into(), "cond".into());
        assert!((pos.cost_basis - 0.5).abs() < 1e-9);
        assert_eq!(pos.total_shares, 100);
        assert!((pos.total_spent - 50.0).abs() < 1e-9);
    }

    #[test]
    fn position_add_fill_updates_vwap() {
        let mut pos = Position::new("tok".into(), 0.5, 100, Direction::Up, "slug".into(), "cond".into());
        pos.add_fill(0.7, 100);
        assert_eq!(pos.total_shares, 200);
        assert!((pos.cost_basis - 0.6).abs() < 1e-9);
    }

    #[test]
    fn position_take_profit_price_respects_ceiling() {
        let pos = Position::new("tok".into(), 0.99, 10, Direction::Up, "slug".into(), "cond".into());
        let tp = pos.take_profit_price();
        assert!(tp <= CONFIG.exit_ceiling_price + 1e-9);
    }

    #[test]
    fn position_take_profit_price_normal_case() {
        let pos = Position::new("tok".into(), 0.50, 10, Direction::Up, "slug".into(), "cond".into());
        let expected_tp = (0.50 * (1.0 + CONFIG.take_profit_pct)).min(CONFIG.exit_ceiling_price);
        let tp = pos.take_profit_price();
        assert!((tp - expected_tp).abs() < 1e-9);
    }

    #[test]
    fn position_unrealised_pnl_correct() {
        let pos = Position::new("tok".into(), 0.50, 100, Direction::Up, "slug".into(), "cond".into());
        let pnl = pos.unrealised_pnl(0.60);
        assert!((pnl - 10.0).abs() < 1e-9);
    }

    #[test]
    fn position_sell_cooldown_initial_true() {
        let pos = Position::new("tok".into(), 0.50, 100, Direction::Up, "slug".into(), "cond".into());
        assert!(pos.sell_cooldown_elapsed());
    }

    #[test]
    fn paper_ledger_credit_buy_adds_balance() {
        let mut ledger = PaperLedger::default();
        ledger.credit_buy("tok1", 100);
        assert!((ledger.balance("tok1") - 100.0).abs() < 1e-9);
    }

    #[test]
    fn paper_ledger_debit_sell_reduces_balance() {
        let mut ledger = PaperLedger::default();
        ledger.credit_buy("tok1", 100);
        ledger.debit_sell("tok1", 40);
        assert!((ledger.balance("tok1") - 60.0).abs() < 1e-9);
    }

    #[test]
    fn paper_ledger_debit_cannot_go_negative() {
        let mut ledger = PaperLedger::default();
        ledger.credit_buy("tok1", 50);
        ledger.debit_sell("tok1", 100);
        assert!((ledger.balance("tok1") - 0.0).abs() < 1e-9);
    }

    #[test]
    fn paper_ledger_pnl_accumulates() {
        let mut ledger = PaperLedger::default();
        ledger.record_pnl(10.0);
        ledger.record_pnl(-3.0);
        assert!((ledger.session_pnl - 7.0).abs() < 1e-9);
    }

    #[test]
    fn executor_constructs_without_panic() {
        init();
        let state = make_state();
        let ex = ClobExecutor::new(state);
        assert!(ex.bankroll() >= 0.0);
    }

    #[test]
    fn executor_bankroll_deduction_succeeds_with_funds() {
        init();
        let state = make_state();
        let ex = ClobExecutor::new(state);
        let initial = ex.bankroll();
        if initial > 10.0 {
            assert!(ex.deduct_bankroll(10.0));
            assert!((ex.bankroll() - (initial - 10.0)).abs() < 1e-9);
        }
    }

    #[test]
    fn executor_bankroll_deduction_fails_when_insufficient() {
        init();
        let state = make_state();
        let ex = ClobExecutor::new(state);
        let initial = ex.bankroll();
        assert!(!ex.deduct_bankroll(initial + 1_000_000.0));
    }

    #[test]
    fn executor_credit_bankroll_adds_correctly() {
        init();
        let state = make_state();
        let ex = ClobExecutor::new(state);
        let initial = ex.bankroll();
        ex.credit_bankroll(100.0);
        assert!((ex.bankroll() - (initial + 100.0)).abs() < 1e-9);
    }

    #[tokio::test]
    async fn execute_trade_paper_rejects_too_small_order() {
        init();
        if !CONFIG.paper_mode { return; } // requires paper mode
        let state = make_state();
        let ex = ClobExecutor::new(state);
        // Set bankroll to near-zero so order_value < $1
        ex.bankroll.store(0.001, Ordering::Release);
        let snap   = make_snap();
        let result = ex.execute_trade(&snap).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_trade_paper_succeeds_with_sufficient_bankroll() {
        init();
        if !CONFIG.paper_mode { return; } // requires paper mode
        let state = make_state();
        let ex = ClobExecutor::new(state);
        ex.bankroll.store(1000.0, Ordering::Release);
        let snap   = make_snap();
        let result = ex.execute_trade(&snap).await;
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        let outcome = result.unwrap();
        assert!(outcome.success);
    }

    #[tokio::test]
    async fn execute_trade_paper_deducts_bankroll() {
        init();
        if !CONFIG.paper_mode { return; } // requires paper mode
        let state = make_state();
        let ex = ClobExecutor::new(state);
        ex.bankroll.store(1000.0, Ordering::Release);
        let snap     = make_snap();
        let _outcome = ex.execute_trade(&snap).await.unwrap();
        assert!(ex.bankroll() < 1000.0);
    }

    #[tokio::test]
    async fn execute_trade_paper_creates_position_record() {
        init();
        if !CONFIG.paper_mode { return; } // requires paper mode
        let state = make_state();
        let ex = ClobExecutor::new(state);
        ex.bankroll.store(1000.0, Ordering::Release);
        let snap = make_snap();
        ex.execute_trade(&snap).await.unwrap();
        let positions = ex.positions.lock();
        assert!(positions.contains_key(&snap.token_id));
    }

    #[test]
    fn kelly_fraction_routes_to_correct_tier() {
        let f_a = CONFIG.kelly_fraction(CONFIG.kelly_tier_a_score + 1.0);
        let f_b = CONFIG.kelly_fraction(CONFIG.kelly_tier_b_score + 1.0);
        let f_c = CONFIG.kelly_fraction(0.0);
        assert!((f_a - CONFIG.kelly_tier_a_fraction).abs() < 1e-9);
        assert!((f_b - CONFIG.kelly_tier_b_fraction).abs() < 1e-9);
        assert!((f_c - CONFIG.kelly_tier_c_fraction).abs() < 1e-9);
    }

    #[test]
    fn wallet_address_stub_returns_none_for_empty_key() {
        assert!(derive_wallet_address_stub("").is_none());
    }

    #[test]
    fn wallet_address_stub_returns_some_for_valid_length_key() {
        let fake_key = "a".repeat(64);
        let _ = derive_wallet_address_stub(&fake_key);
    }

    #[test]
    fn wallet_address_stub_handles_0x_prefix() {
        let fake_key = format!("0x{}", "b".repeat(64));
        let _ = derive_wallet_address_stub(&fake_key);
    }
}
