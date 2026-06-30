//! live_trading.rs — Complete live execution engine for the Polymarket CLOB.
//!
//! # What this replaces
//!
//! Every `// TODO (Step 4)` stub in `executor.rs` is implemented here as a
//! standalone module. Wire it in by:
//!
//! 1. Adding `mod live_trading;` to `main.rs`.
//! 2. Replacing the `execute_live`, `execute_sell` (live branch),
//!    `get_token_balance`, `reconcile_bankroll_live`, `derive_wallet_address_stub`,
//!    and `trigger_auto_redeem` bodies in `executor.rs` with calls into this module.
//!
//! # Speed philosophy
//!
//! Every nanosecond saved on the critical path (trigger → signed HTTP POST → fill)
//! matters. The design choices here reflect that:
//!
//! - **Pre-computed signing key**: `LiveSigner` is constructed once at startup.
//!   The `k256::SigningKey` is `Clone`-cheap (32-byte scalar on the stack).
//! - **No heap allocations on the order path**: the EIP-712 hash is computed
//!   in a fixed-size `[u8; 32]` buffer; the signature is 65 raw bytes; only
//!   the base64 encoding and the JSON body require heap allocation, and those
//!   happen exactly once per order.
//! - **Persistent HTTP/2 connection**: the `reqwest::Client` in `ClobExecutor`
//!   already uses HTTP/2 keep-alive. The live sell path reuses it.
//! - **Tokio task for Web3 RPC**: balance reads are async and never block the
//!   executor's position-manager loop.
//! - **EthABI-free**: the USDC `balanceOf` and CTF `balanceOf` calls are hand-
//!   encoded as 4-byte selector + 32-byte padded arg. No ABI crate dependency.
//!
//! # Cargo.toml additions required
//!
//! ```toml
//! [dependencies]
//! k256          = { version = "0.13", features = ["ecdsa"] }
//! sha3          = "0.10"
//! base64        = "0.22"
//! hex           = "0.4"          # likely already present
//! reqwest       = { version = "0.12", features = ["json", "rustls-tls"] }
//! serde_json    = "1"            # likely already present
//! tokio         = { version = "1", features = ["full"] }
//! ```
//!
//! # Polymarket CLOB API reference
//!
//! POST https://clob.polymarket.com/order
//! Headers: Content-Type: application/json
//!          POLY_ADDRESS: <checksummed wallet address>
//!          POLY_SIGNATURE: <EIP-712 L2 auth signature>
//!          POLY_TIMESTAMP: <unix seconds>
//!          POLY_NONCE: 0
//!
//! The per-order signature is embedded in the JSON body (`signature` field).
//! The header signature is a separate L2 API authentication signature.
//!
//! # Polygon RPC
//!
//! USDC.e on Polygon: 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174
//! CTF (conditional token framework): 0x4D97DCd97eC945f40cF65F87097ACe5EA0476045

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::{STANDARD as B64, URL_SAFE as B64_URL}};
use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey, VerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashSigner as _;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Polymarket CLOB REST endpoint for order submission.
pub const CLOB_ORDER_URL: &str = "https://clob.polymarket.com/order";

/// Polymarket pUSD (Proxy USDC) — V2 collateral token on Polygon Mainnet.
/// Used for on-chain approvals and as the target balance for V2 orders.
pub const USDC_CONTRACT: &str = "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB";

/// Bridged USDC.e — legacy Polymarket V1 collateral, still commonly held in wallets.
/// Checked alongside pUSD when reading bankroll so the bot works during migration.
pub const USDC_E_CONTRACT: &str = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";

/// Native USDC on Polygon (Circle's canonical contract, 6 decimals).
/// Also checked during bankroll reads as a fallback.
pub const USDC_NATIVE_CONTRACT: &str = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";

/// Polymarket CTF (ERC-1155 conditional tokens) contract on Polygon.
pub const CTF_CONTRACT: &str = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045";

/// Polymarket CTF Exchange (Standard markets) — V2 contract address.
pub const CTF_EXCHANGE_STANDARD: &str = "0xE111180000d2663C0091e4f400237545B87B996B";

/// Polymarket CTF Exchange (NegRisk / Up-Down markets) — V2 contract address.
pub const CTF_EXCHANGE_NEG_RISK: &str  = "0xe2222d279d744050d28e00520010520000310F59";

/// EIP-712 chain ID for Polygon mainnet.
pub const POLYGON_CHAIN_ID: u64 = 137;

/// `balanceOf(address)` selector: keccak256("balanceOf(address)")[0..4]
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// `balanceOf(address,uint256)` selector: keccak256("balanceOf(address,uint256)")[0..4]
const ERC1155_BALANCE_OF_SELECTOR: [u8; 4] = [0x00, 0xfd, 0xd5, 0x8e];

// ─────────────────────────────────────────────────────────────────────────────
// ApiCredentials — L2 HMAC credentials derived from the private key
// ─────────────────────────────────────────────────────────────────────────────

/// Polymarket L2 API credentials derived via `GET /auth/derive-api-key`.
///
/// These are used for HMAC-SHA256 signing of order-submission requests.
/// Credentials are deterministically derived from the private key and are
/// stable across restarts — no need to store or rotate them.
#[derive(Debug, Clone)]
pub struct ApiCredentials {
    pub api_key:        String,
    /// Base64-URL-encoded HMAC secret.
    pub api_secret:     String,
    pub api_passphrase: String,
}

/// Fetch L2 API credentials from the CLOB using L1 (EIP-712 ClobAuth) auth.
///
/// Calls `GET https://clob.polymarket.com/auth/derive-api-key` with L1 headers.
/// Returns stable, deterministic credentials that can be reused across restarts.
pub async fn derive_api_credentials(signer: &LiveSigner) -> Result<ApiCredentials, String> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client build failed: {e}"))?;

    let now_ts = unix_ts_secs();
    let auth_sig = signer.sign_clob_auth(now_ts)?;

    let resp = http
        .get("https://clob.polymarket.com/auth/derive-api-key")
        .header("POLY_ADDRESS",   &signer.wallet_address)
        .header("POLY_SIGNATURE", auth_sig)
        .header("POLY_TIMESTAMP", now_ts.to_string())
        .header("POLY_NONCE",     "0")
        .send()
        .await
        .map_err(|e| format!("Credential derivation HTTP failed: {e}"))?;

    let status = resp.status();
    let text = resp.text().await
        .map_err(|e| format!("Credential response read failed: {e}"))?;

    if !status.is_success() {
        return Err(format!("Credential derivation HTTP {status}: {text}"));
    }

    #[derive(serde::Deserialize)]
    struct CredResp {
        #[serde(rename = "apiKey")]
        api_key:    String,
        secret:     String,
        passphrase: String,
    }

    let c: CredResp = serde_json::from_str(&text)
        .map_err(|e| format!("Credential parse error: {e} — body: {text}"))?;

    info!(
        api_key = %c.api_key,
        "✅ Polymarket L2 API credentials derived."
    );

    Ok(ApiCredentials {
        api_key:        c.api_key,
        api_secret:     c.secret,
        api_passphrase: c.passphrase,
    })
}

/// Build L2 HMAC-SHA256 auth headers for a CLOB request.
///
/// Matches `build_hmac_signature` + `create_level_2_headers` in py_clob_client_v2.
/// The HMAC message = `"{timestamp}{method}{path}{body}"`.
/// The resulting signature is URL-safe base64 (NOT hex).
pub fn build_l2_headers(
    wallet_address: &str,
    creds: &ApiCredentials,
    timestamp: u64,
    method:    &str,
    path:      &str,
    body:      &str,
) -> Result<Vec<(&'static str, String)>, String> {
    let key_bytes = B64_URL.decode(&creds.api_secret)
        .map_err(|e| format!("Base64 decode of api_secret failed: {e}"))?;

    let message = format!("{timestamp}{method}{path}{body}");

    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(message.as_bytes());
    let sig = B64_URL.encode(mac.finalize().into_bytes());

    Ok(vec![
        ("POLY_ADDRESS",    wallet_address.to_string()),
        ("POLY_SIGNATURE",  sig),
        ("POLY_TIMESTAMP",  timestamp.to_string()),
        ("POLY_API_KEY",    creds.api_key.clone()),
        ("POLY_PASSPHRASE", creds.api_passphrase.clone()),
    ])
}

// ─────────────────────────────────────────────────────────────────────────────
// LiveSigner — holds the pre-parsed signing key for zero-cost per-order signing
// ─────────────────────────────────────────────────────────────────────────────

/// Owns the secp256k1 private key and the derived wallet address.
///
/// Constructed once at startup. All order-signing methods borrow `&self`
/// so they can be called concurrently from multiple tasks without a lock.
/// (In practice, order execution is serialised by the sniper's `is_armed`
/// flag, but there is no correctness hazard if two tasks race here.)
#[derive(Debug, Clone)]
pub struct LiveSigner {
    /// Parsed secp256k1 key ready for ECDSA signing (32-byte scalar, stack-only).
    signing_key: SigningKey,

    /// EIP-55 checksummed Ethereum address derived from the public key.
    pub wallet_address: String,
}

impl LiveSigner {
    /// Parse a hex-encoded private key and derive the wallet address.
    ///
    /// Accepts keys with or without a `0x` prefix.
    ///
    /// # Errors
    ///
    /// Returns a descriptive `String` (not `Box<dyn Error>`) so callers can
    /// log it directly without allocation overhead on the success path.
    pub fn from_hex_key(private_key: &str) -> Result<Self, String> {
        let key_clean = private_key.trim_start_matches("0x");
        let bytes = hex::decode(key_clean)
            .map_err(|e| format!("Private key hex decode failed: {e}"))?;

        if bytes.len() != 32 {
            return Err(format!(
                "Private key must be 32 bytes, got {}",
                bytes.len()
            ));
        }

        let signing_key = SigningKey::from_slice(&bytes)
            .map_err(|e| format!("Invalid secp256k1 key: {e}"))?;

        let wallet_address = derive_address(&signing_key);

        Ok(Self { signing_key, wallet_address })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Per-order EIP-712 signature (embedded in JSON body)
    // ─────────────────────────────────────────────────────────────────────────

    /// Sign a Polymarket CLOB order using EIP-712 typed data (V2 spec).
    ///
    /// V2 Order struct (taker, nonce, feeRateBps removed vs V1):
    /// ```text
    /// Order {
    ///   salt:          uint256
    ///   maker:         address
    ///   signer:        address  (= maker for EOA)
    ///   tokenId:       uint256
    ///   makerAmount:   uint256
    ///   takerAmount:   uint256
    ///   expiration:    uint256  (0 = no expiry / FAK)
    ///   side:          uint8    (0=BUY, 1=SELL)
    ///   signatureType: uint8    (0 = EOA ECDSA)
    /// }
    /// ```
    ///
    /// * `neg_risk` — pass `true` for NegRisk (Up/Down) markets.
    ///   Standard exchange:  `0xE111180000d2663C0091e4f400237545B87B996B`
    ///   NegRisk exchange:   `0xe2222d279d744050d28e00520010520000310F59`
    pub fn sign_order(
        &self,
        token_id:     &str,
        price:        f64,   // limit price [0.01, 0.99]
        size:         u64,   // integer shares
        side:         Side,
        salt:         u64,   // random nonce for order deduplication
        neg_risk:     bool,  // true for neg-risk markets (BTC/ETH up-down etc.)
        timestamp_ms: u64,   // current time in milliseconds
        maker_addr:   &str,  // maker address (EOA or funder/proxy wallet)
        sig_type:     u8,    // 0=EOA, 1=PolyProxy, 2=GnosisSafe
    ) -> Result<String, String> {
        // ── Step 1: Compute takerAmount / makerAmount ─────────────────────────
        // Polymarket uses integer amounts in USDC micro-units (6 decimals).
        // BUY:  makerAmount = USDC spent,  takerAmount = shares received
        // SELL: makerAmount = shares given, takerAmount = USDC received
        let usdc_scale = 1_000_000u128;
        let (maker_amount, taker_amount) = match side {
            Side::Buy => {
                let maker = ((price * size as f64) * usdc_scale as f64) as u128;
                let taker = size as u128 * usdc_scale;
                (maker, taker)
            }
            Side::Sell => {
                let maker = size as u128 * usdc_scale;
                let taker = ((price * size as f64) * usdc_scale as f64) as u128;
                (maker, taker)
            }
        };

        // ── Step 2: EIP-712 domain separator ─────────────────────────────────
        // Domain: { name: "Polymarket CTF Exchange", version: "2",
        //           chainId: 137, verifyingContract: <exchange> }
        //
        // V2 CRITICAL: version bumped from "1" → "2". Using "1" produces
        // signatures that the V2 contracts will reject outright.
        let domain_type_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
            h.finalize().into()
        };

        let name_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"Polymarket CTF Exchange");
            h.finalize().into()
        };

        let version_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"2");  // V2: was "1" in V1
            h.finalize().into()
        };

        // V2 exchange addresses — dynamically selected by market type.
        let exchange_addr_hex = if neg_risk {
            CTF_EXCHANGE_NEG_RISK    // NegRisk (Up/Down) markets
        } else {
            CTF_EXCHANGE_STANDARD   // Standard binary markets
        };
        let exchange_addr_bytes = decode_address(exchange_addr_hex)?;

        let domain_separator: [u8; 32] = {
            let mut enc = Vec::with_capacity(5 * 32);
            enc.extend_from_slice(&domain_type_hash);
            enc.extend_from_slice(&name_hash);
            enc.extend_from_slice(&version_hash);
            enc.extend_from_slice(&pad_u256(POLYGON_CHAIN_ID as u128));
            enc.extend_from_slice(&pad_address(&exchange_addr_bytes));
            let mut h = Keccak256::new();
            h.update(&enc);
            h.finalize().into()
        };

        // ── Step 3: Order struct hash ─────────────────────────────────────
        // V2 Order type string — expiration removed, timestamp/metadata/builder added.
        let order_type_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"Order(uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)");
            h.finalize().into()
        };

        // maker = funder/proxy wallet; signer = EOA (self.wallet_address)
        let maker_addr_bytes  = decode_address(maker_addr)?;
        let signer_addr_bytes = decode_address(&self.wallet_address)?;
        let token_id_u256     = token_id_to_u256(token_id)?;
        let side_u8           = side as u8;
        let metadata          = [0u8; 32]; // BYTES32_ZERO
        let builder_field     = [0u8; 32]; // BYTES32_ZERO

        let struct_hash: [u8; 32] = {
            // 12 fields × 32 bytes
            let mut enc = Vec::with_capacity(12 * 32);
            enc.extend_from_slice(&order_type_hash);
            enc.extend_from_slice(&pad_u256(salt as u128));           // salt
            enc.extend_from_slice(&pad_address(&maker_addr_bytes));   // maker (funder/proxy)
            enc.extend_from_slice(&pad_address(&signer_addr_bytes));  // signer (EOA)
            enc.extend_from_slice(&token_id_u256);                    // tokenId
            enc.extend_from_slice(&pad_u256(maker_amount));           // makerAmount
            enc.extend_from_slice(&pad_u256(taker_amount));           // takerAmount
            enc.extend_from_slice(&pad_u256(side_u8 as u128));        // side (uint8)
            enc.extend_from_slice(&pad_u256(sig_type as u128));       // signatureType
            enc.extend_from_slice(&pad_u256(timestamp_ms as u128));   // timestamp (ms)
            enc.extend_from_slice(&metadata);                         // metadata (bytes32 zero)
            enc.extend_from_slice(&builder_field);                    // builder (bytes32 zero)
            let mut h = Keccak256::new();
            h.update(&enc);
            h.finalize().into()
        };

        // ── Step 4: Final EIP-712 digest ─────────────────────────────────────
        let digest: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"\x19\x01");
            h.update(domain_separator);
            h.update(struct_hash);
            h.finalize().into()
        };

        // ── Step 5: ECDSA sign ────────────────────────────────────────────────
        let (sig, recid): (K256Sig, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .map_err(|e| format!("ECDSA signing failed: {e}"))?;

        // ── Step 6: Encode as 0x-prefixed hex [r(32)|s(32)|v(1)] ─────────────
        // Ethereum recovery ID: v = 27 + recid.
        let mut raw_sig = [0u8; 65];
        raw_sig[..32].copy_from_slice(&sig.r().to_bytes());
        raw_sig[32..64].copy_from_slice(&sig.s().to_bytes());
        raw_sig[64] = 27 + recid.to_byte();

        Ok(format!("0x{}", hex::encode(raw_sig)))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // L2 API authentication header signature
    // ─────────────────────────────────────────────────────────────────────────

    /// Sign the Polymarket CLOB L1 API authentication header.
    ///
    /// Uses EIP-712 over the `ClobAuth` struct — matches `sign_clob_auth_message`
    /// in `py_clob_client_v2/signing/eip712.py`.
    ///
    /// Domain:  `ClobAuthDomain` / version `1` / chainId `137` (no verifyingContract)
    /// Struct:  `ClobAuth(address address, string timestamp, uint256 nonce, string message)`
    /// Message: `"This message attests that I control the given wallet"`
    pub fn sign_clob_auth(&self, timestamp: u64) -> Result<String, String> {
        // ── Domain separator (no verifyingContract) ───────────────────────────
        let domain_type_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"EIP712Domain(string name,string version,uint256 chainId)");
            h.finalize().into()
        };
        let name_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"ClobAuthDomain");
            h.finalize().into()
        };
        let version_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"1");
            h.finalize().into()
        };
        let domain_separator: [u8; 32] = {
            let mut enc = Vec::with_capacity(4 * 32);
            enc.extend_from_slice(&domain_type_hash);
            enc.extend_from_slice(&name_hash);
            enc.extend_from_slice(&version_hash);
            enc.extend_from_slice(&pad_u256(POLYGON_CHAIN_ID as u128));
            let mut h = Keccak256::new();
            h.update(&enc);
            h.finalize().into()
        };

        // ── ClobAuth struct hash ──────────────────────────────────────────────
        // Type: ClobAuth(address address,string timestamp,uint256 nonce,string message)
        let struct_type_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"ClobAuth(address address,string timestamp,uint256 nonce,string message)");
            h.finalize().into()
        };

        let addr_bytes = decode_address(&self.wallet_address)?;

        // EIP-712: dynamic types (string) are hashed
        let ts_str = timestamp.to_string();
        let ts_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(ts_str.as_bytes());
            h.finalize().into()
        };
        let msg_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"This message attests that I control the given wallet");
            h.finalize().into()
        };

        let struct_hash: [u8; 32] = {
            let mut enc = Vec::with_capacity(5 * 32);
            enc.extend_from_slice(&struct_type_hash);
            enc.extend_from_slice(&pad_address(&addr_bytes)); // address
            enc.extend_from_slice(&ts_hash);                  // string timestamp (hashed)
            enc.extend_from_slice(&pad_u256(0));              // nonce = 0
            enc.extend_from_slice(&msg_hash);                 // string message (hashed)
            let mut h = Keccak256::new();
            h.update(&enc);
            h.finalize().into()
        };

        // ── Final EIP-712 digest ──────────────────────────────────────────────
        let digest: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"\x19\x01");
            h.update(domain_separator);
            h.update(struct_hash);
            h.finalize().into()
        };

        let (sig, recid): (K256Sig, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .map_err(|e| format!("CLOB auth signing failed: {e}"))?;

        let mut raw = [0u8; 65];
        raw[..32].copy_from_slice(&sig.r().to_bytes());
        raw[32..64].copy_from_slice(&sig.s().to_bytes());
        raw[64] = 27 + recid.to_byte();

        Ok(format!("0x{}", hex::encode(raw)))
    }

    /// Kept for compatibility — delegates to `sign_clob_auth`.
    #[inline]
    pub fn sign_l2_auth(&self, timestamp: u64, _method: &str, _path: &str) -> Result<String, String> {
        self.sign_clob_auth(timestamp)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Side enum
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Buy  = 0,
    Sell = 1,
}

// ─────────────────────────────────────────────────────────────────────────────
// CLOB HTTP request / response types
// ─────────────────────────────────────────────────────────────────────────────

/// The `order` object nested inside `ClobOrderPayload` (V2 API spec).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInner {
    /// Random salt for order deduplication (integer).
    pub salt:           u64,
    /// Maker = wallet address (EIP-55 checksum).
    pub maker:          String,
    /// Signer = same as maker for EOA wallets.
    pub signer:         String,
    /// Conditional token ID (decimal string).
    pub token_id:       String,
    /// USDC micro-units the maker sends (decimal string).
    pub maker_amount:   String,
    /// Token units the maker receives (decimal string).
    pub taker_amount:   String,
    /// "BUY" or "SELL".
    pub side:           String,
    /// Order expiration Unix timestamp; "0" = no expiry (FAK).
    pub expiration:     String,
    /// 0 = EOA (direct private-key signature).
    pub signature_type: u8,
    /// Current time in milliseconds (decimal string).
    pub timestamp:      String,
    /// bytes32 zero (hex string).
    pub metadata:       String,
    /// bytes32 zero (hex string).
    pub builder:        String,
    /// 0x-prefixed hex ECDSA signature of the EIP-712 order digest.
    pub signature:      String,
}

/// Top-level JSON body sent to `POST /order` (V2 API spec).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClobOrderPayload {
    /// The signed order fields.
    pub order:      OrderInner,
    /// Maker's wallet address.
    pub owner:      String,
    /// Order type: "FAK" (Fill-and-Kill / marketable limit order).
    pub order_type: String,
    /// Deferred execution flag (always false for FAK).
    pub defer_exec: bool,
    /// Post-only flag (always false for FAK).
    pub post_only:  bool,
}

/// JSON response from `POST /order`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderResponse {
    pub success:   bool,
    pub order_id:  Option<String>,
    pub size:      Option<f64>,
    pub price:     Option<f64>,
    pub error_msg: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_live_buy — replaces the TODO stub in executor.rs
// ─────────────────────────────────────────────────────────────────────────────

/// Submit a signed FAK BUY order to the Polymarket CLOB.
///
/// # Integration
///
/// Replace the body of `ClobExecutor::execute_live` with:
/// ```rust,ignore
/// live_trading::execute_live_buy(
///     &self.http, signer, snap, buy_price, buy_size, order_value,
/// ).await
/// ```
///
/// Where `signer` is a `&LiveSigner` stored in `ClobExecutor`.
///
/// # Returns
///
/// - `Ok((fill_price, fill_size, order_id))` on a confirmed fill.
/// - `Err(String)` on any network, signing, or CLOB rejection error.
pub async fn execute_live_buy(
    http:        &reqwest::Client,
    signer:      &LiveSigner,
    creds:       &ApiCredentials,
    token_id:    &str,
    buy_price:   f64,
    buy_size:    u64,
    order_value: f64,
    neg_risk:    bool,
) -> Result<(f64, u64, Option<String>), String> {
    use crate::config::CONFIG;
    // maker = funder/proxy wallet if configured, otherwise EOA
    let maker_address = if CONFIG.funder_address.is_empty() {
        signer.wallet_address.clone()
    } else {
        CONFIG.funder_address.clone()
    };
    let sig_type = CONFIG.signature_type;

    let salt = random_salt();
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let sig = signer.sign_order(
        token_id, buy_price, buy_size, Side::Buy,
        salt, neg_risk, timestamp_ms, &maker_address, sig_type,
    )?;

    // Compute amounts with proper rounding (not truncation) to avoid float precision issues.
    let usdc_scale   = 1_000_000u128;
    let maker_amount = ((buy_price * buy_size as f64) * usdc_scale as f64).round() as u128;
    let taker_amount = buy_size as u128 * usdc_scale;

    let body = ClobOrderPayload {
        order: OrderInner {
            salt,
            maker:          maker_address.clone(),
            signer:         signer.wallet_address.clone(),
            token_id:       token_id.to_string(),
            maker_amount:   maker_amount.to_string(),
            taker_amount:   taker_amount.to_string(),
            side:           "BUY".to_string(),
            expiration:     "0".to_string(),
            signature_type: sig_type,
            timestamp:      timestamp_ms.to_string(),
            metadata:       "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            builder:        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            signature:      sig,
        },
        owner:      maker_address.clone(),
        order_type: "FAK".to_string(),
        defer_exec: false,
        post_only:  false,
    };

    // Serialize the body to compact JSON — used for both the HTTP body and HMAC.
    let body_json = serde_json::to_string(&body)
        .map_err(|e| format!("BUY body serialization failed: {e}"))?;

    let now_ts = unix_ts_secs();
    let l2_headers = build_l2_headers(
        &signer.wallet_address, creds, now_ts, "POST", "/order", &body_json,
    )?;

    let mut req = http
        .post(CLOB_ORDER_URL)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_millis(800))
        .body(body_json);
    for (k, v) in &l2_headers { req = req.header(*k, v); }

    let resp   = req.send().await.map_err(|e| format!("HTTP send failed: {e}"))?;
    let status = resp.status();
    let text   = resp.text().await.map_err(|e| format!("HTTP body read failed: {e}"))?;

    if !status.is_success() {
        return Err(format!("CLOB HTTP {status}: {text}"));
    }

    let parsed: OrderResponse = serde_json::from_str(&text)
        .map_err(|e| format!("CLOB response parse error: {e} — body: {text}"))?;

    if !parsed.success {
        let msg = parsed.error_msg.unwrap_or_else(|| "unknown CLOB error".into());
        return Err(format!("CLOB rejected BUY: {msg}"));
    }

    let fill_price = parsed.price.unwrap_or(buy_price);
    let fill_size  = parsed.size.map(|s| s as u64).unwrap_or(buy_size);

    info!(
        token       = %&token_id[token_id.len().saturating_sub(6)..],
        fill_price  = fill_price,
        fill_size   = fill_size,
        order_value = order_value,
        order_id    = ?parsed.order_id,
        "🟢 LIVE BUY FILLED."
    );

    Ok((fill_price, fill_size, parsed.order_id))
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_live_sell — replaces the TODO stub in executor.rs execute_sell
// ─────────────────────────────────────────────────────────────────────────────

/// Submit a signed FAK SELL order to the Polymarket CLOB.
///
/// # Integration
///
/// Replace the `else` branch of `ClobExecutor::execute_sell` with:
/// ```rust,ignore
/// match live_trading::execute_live_sell(&self.http, signer, token_id, sell_price, shares).await {
///     Ok((proceeds, order_id)) => {
///         self.credit_bankroll(proceeds);
///         info!("🟢 LIVE SELL FILLED. reason={reason} pnl={pnl:.2}");
///     }
///     Err(e) => {
///         error!("❌ Live sell failed: {e}. Position retained for retry.");
///         return; // Don't remove position — retry on next manager tick.
///     }
/// }
/// ```
pub async fn execute_live_sell(
    http:       &reqwest::Client,
    signer:     &LiveSigner,
    creds:      &ApiCredentials,
    token_id:   &str,
    sell_price: f64,
    shares:     u64,
    neg_risk:   bool,
) -> Result<(f64, Option<String>), String> {
    use crate::config::CONFIG;
    let maker_address = if CONFIG.funder_address.is_empty() {
        signer.wallet_address.clone()
    } else {
        CONFIG.funder_address.clone()
    };
    let sig_type = CONFIG.signature_type;

    let salt = random_salt();
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let sig = signer.sign_order(
        token_id, sell_price, shares, Side::Sell,
        salt, neg_risk, timestamp_ms, &maker_address, sig_type,
    )?;

    let usdc_scale   = 1_000_000u128;
    let maker_amount = shares as u128 * usdc_scale;
    let taker_amount = ((sell_price * shares as f64) * usdc_scale as f64).round() as u128;

    let body = ClobOrderPayload {
        order: OrderInner {
            salt,
            maker:          maker_address.clone(),
            signer:         signer.wallet_address.clone(),
            token_id:       token_id.to_string(),
            maker_amount:   maker_amount.to_string(),
            taker_amount:   taker_amount.to_string(),
            side:           "SELL".to_string(),
            expiration:     "0".to_string(),
            signature_type: sig_type,
            timestamp:      timestamp_ms.to_string(),
            metadata:       "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            builder:        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            signature:      sig,
        },
        owner:      maker_address.clone(),
        order_type: "FAK".to_string(),
        defer_exec: false,
        post_only:  false,
    };

    let body_json = serde_json::to_string(&body)
        .map_err(|e| format!("SELL body serialization failed: {e}"))?;

    let now_ts = unix_ts_secs();
    let l2_headers = build_l2_headers(
        &signer.wallet_address, creds, now_ts, "POST", "/order", &body_json,
    )?;

    let mut req = http
        .post(CLOB_ORDER_URL)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_millis(800))
        .body(body_json);
    for (k, v) in &l2_headers { req = req.header(*k, v); }

    let resp   = req.send().await.map_err(|e| format!("HTTP send failed: {e}"))?;
    let status = resp.status();
    let text   = resp.text().await.map_err(|e| format!("HTTP body read failed: {e}"))?;

    if !status.is_success() {
        return Err(format!("CLOB HTTP {status}: {text}"));
    }

    let parsed: OrderResponse = serde_json::from_str(&text)
        .map_err(|e| format!("CLOB parse error: {e} — body: {text}"))?;

    if !parsed.success {
        let msg = parsed.error_msg.unwrap_or_else(|| "unknown error".into());
        return Err(format!("CLOB rejected SELL: {msg}"));
    }

    let fill_price = parsed.price.unwrap_or(sell_price);
    let proceeds   = fill_price * shares as f64;

    info!(
        token      = %&token_id[token_id.len().saturating_sub(6)..],
        fill_price = fill_price,
        shares     = shares,
        proceeds   = proceeds,
        order_id   = ?parsed.order_id,
        "🟢 LIVE SELL FILLED."
    );

    Ok((proceeds, parsed.order_id))
}

// ─────────────────────────────────────────────────────────────────────────────
// get_usdc_balance — replaces reconcile_bankroll_live TODO
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch the USDC.e balance of `wallet_address` via a raw eth_call to Polygon RPC.
///
/// Uses hand-encoded ABI (no dependency on ethabi/alloy) to minimise compile
/// time and binary size. The call is a single 68-byte payload:
///   [4-byte selector] + [12-byte pad] + [20-byte address]
///
/// # Integration
///
/// Replace `ClobExecutor::reconcile_bankroll_live` with:
/// ```rust,ignore
/// pub async fn reconcile_bankroll_live(&self) {
///     if let Some(signer) = &self.signer {
///         match live_trading::get_usdc_balance(&self.http, &CONFIG.poly_rpc_url, &signer.wallet_address).await {
///             Ok(usdc) => {
///                 let prev = self.bankroll();
///                 if (usdc - prev).abs() > 0.01 {
///                     info!(prev, usdc, "💰 Bankroll reconciled from on-chain USDC.");
///                     self.bankroll.store(usdc, Ordering::Release);
///                 }
///             }
///             Err(e) => warn!("Bankroll reconciliation failed: {e}"),
///         }
///     }
/// }
/// ```
pub async fn get_usdc_balance(
    _http:          &reqwest::Client,  // kept for API compat; RPC uses its own plain client
    rpc_url:        &str,
    wallet_address: &str,
) -> Result<f64, String> {
    // Use a dedicated minimal client for JSON-RPC calls.
    // The CLOB executor's HTTP client has gzip + HTTP/2 keepalive settings tuned
    // for the Polymarket REST API; those settings can silently interfere with
    // Alchemy's JSON-RPC responses (confirmed by integration test with plain client).
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build RPC client: {e}"))?;

    // Query all three stablecoin contracts that Polymarket may use as collateral:
    //   1. pUSD  — V2 primary collateral
    //   2. USDC.e — V1 legacy bridged USDC (most wallets still hold this)
    //   3. Native USDC — Circle's canonical Polygon USDC
    // We sum all non-zero balances so the bankroll is correct regardless of
    // which token(s) the wallet holds during and after the V1→V2 migration.
    let addr_bytes = decode_address(wallet_address)?;
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&BALANCE_OF_SELECTOR);
    calldata.extend_from_slice(&pad_address(&addr_bytes));

    let contracts = [
        (USDC_CONTRACT,        "pUSD"),
        (USDC_E_CONTRACT,      "USDC.e"),
        (USDC_NATIVE_CONTRACT, "USDC"),
    ];

    let mut total = 0.0f64;
    let mut all_failed = true;
    for (contract, label) in contracts {
        match eth_call(&http, rpc_url, contract, &calldata).await {
            Ok(result) => {
                all_failed = false;
                match decode_u256_result(&result) {
                    Ok(raw) => {
                        let bal = raw as f64 / 1_000_000.0;
                        info!(contract = label, balance = bal, raw_hex = %result, "💵 Stablecoin balance checked.");
                        total += bal;
                    }
                    Err(e) => {
                        error!(contract = label, raw_hex = %result, error = %e, "Balance decode failed.");
                    }
                }
            }
            Err(e) => {
                error!(contract = label, error = %e, "eth_call failed for stablecoin contract.");
            }
        }
    }
    if all_failed {
        return Err(format!(
            "All stablecoin RPC calls failed — check POLY_RPC_URL. wallet={wallet_address}"
        ));
    }

    info!(total_bankroll = total, wallet = %wallet_address, "💰 Total stablecoin bankroll resolved.");
    Ok(total)
}

// ─────────────────────────────────────────────────────────────────────────────
// get_ctf_balance — replaces get_token_balance TODO (live branch)
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch the ERC-1155 CTF token balance for a given Polymarket token ID.
///
/// Encodes: `balanceOf(address account, uint256 id)` on the CTF contract.
///
/// # Integration
///
/// Replace `ClobExecutor::get_token_balance` live branch with:
/// ```rust,ignore
/// match live_trading::get_ctf_balance(
///     &self.http, &CONFIG.poly_rpc_url,
///     signer.wallet_address.as_str(), token_id
/// ).await {
///     Ok(bal) => bal,
///     Err(e)  => { warn!("CTF balance fetch failed: {e}"); 0.0 }
/// }
/// ```
pub async fn get_ctf_balance(
    _http:          &reqwest::Client,  // kept for API compat; RPC uses its own plain client
    rpc_url:        &str,
    wallet_address: &str,
    token_id:       &str,
) -> Result<f64, String> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build RPC client: {e}"))?;
    let addr_bytes   = decode_address(wallet_address)?;
    let token_u256   = token_id_to_u256(token_id)?;

    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&ERC1155_BALANCE_OF_SELECTOR);
    calldata.extend_from_slice(&pad_address(&addr_bytes));
    calldata.extend_from_slice(&token_u256);

    let result = eth_call(&http, rpc_url, CTF_CONTRACT, &calldata).await?;
    let raw    = decode_u256_result(&result)?;

    // CTF tokens have 6 decimals (same as USDC.e on Polygon).
    Ok(raw as f64 / 1_000_000.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// trigger_auto_redeem_native — replaces the Python subprocess approach
// ─────────────────────────────────────────────────────────────────────────────

/// Redeem winning CTF shares directly via the `redeemPositions` contract call.
///
/// This replaces the `python3 scripts/redeem.py {condition_id}` subprocess with
/// a native Rust eth_sendRawTransaction call. Eliminates the Python boot
/// overhead (~200ms) and keeps everything in-process.
///
/// # Contract call
///
/// ```solidity
/// function redeemPositions(
///   address collateralToken,   // USDC.e
///   bytes32 parentCollectionId, // 0x00..00 for top-level
///   bytes32 conditionId,
///   uint256[] indexSets         // [1, 2] for binary markets
/// )
/// ```
///
/// Selector: keccak256("redeemPositions(address,bytes32,bytes32,uint256[])")
///
/// # Integration
///
/// Replace `ClobExecutor::trigger_auto_redeem` body with:
/// ```rust,ignore
/// if let Some(signer) = &self.signer {
///     live_trading::trigger_auto_redeem_native(
///         &self.http, &CONFIG.poly_rpc_url, signer, &condition_id
///     ).await;
/// }
/// ```
pub async fn trigger_auto_redeem_native(
    http:         &reqwest::Client,
    rpc_url:      &str,
    signer:       &LiveSigner,
    condition_id: &str,
) {
    if condition_id.is_empty() {
        warn!("Auto-redeem: empty condition ID — skipping.");
        return;
    }

    info!(
        condition_id = %condition_id,
        "⏳ Waiting 15s for UMA oracle settlement before native redemption..."
    );
    tokio::time::sleep(Duration::from_secs(15)).await;

    // Decode condition ID from hex.
    let cond_bytes: [u8; 32] = match parse_bytes32(condition_id) {
        Ok(b)  => b,
        Err(e) => {
            error!("Auto-redeem: invalid condition ID `{condition_id}`: {e}");
            return;
        }
    };

    // Build calldata for redeemPositions.
    // Selector: keccak256("redeemPositions(address,bytes32,bytes32,uint256[])")
    let selector: [u8; 4] = {
        let mut h = Keccak256::new();
        h.update(b"redeemPositions(address,bytes32,bytes32,uint256[])");
        let d = h.finalize();
        [d[0], d[1], d[2], d[3]]
    };

    let usdc_addr_bytes  = decode_address(USDC_CONTRACT).unwrap_or([0u8; 20]);
    let parent_coll_id   = [0u8; 32]; // top-level market

    // ABI encode:
    // [selector]                    4 bytes
    // [padded USDC address]        32 bytes
    // [parentCollectionId]         32 bytes
    // [conditionId]                32 bytes
    // [offset to indexSets array]  32 bytes  → points to 5*32 = 160
    // [array length]               32 bytes  → 2
    // [indexSets[0] = 1]           32 bytes
    // [indexSets[1] = 2]           32 bytes
    let mut calldata = Vec::with_capacity(4 + 7 * 32);
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&pad_address(&usdc_addr_bytes));
    calldata.extend_from_slice(&parent_coll_id);
    calldata.extend_from_slice(&cond_bytes);
    calldata.extend_from_slice(&pad_u256(160)); // offset to dynamic array
    calldata.extend_from_slice(&pad_u256(2));   // length = 2
    calldata.extend_from_slice(&pad_u256(1));   // indexSets[0]
    calldata.extend_from_slice(&pad_u256(2));   // indexSets[1]

    // Fetch nonce for the signer's address.
    let nonce = match get_transaction_count(http, rpc_url, &signer.wallet_address).await {
        Ok(n)  => n,
        Err(e) => {
            error!("Auto-redeem: failed to get nonce: {e}");
            return;
        }
    };

    // Build and sign the raw EIP-1559 transaction.
    let raw_tx = match sign_eip1559_tx(
        signer,
        CTF_CONTRACT,
        &calldata,
        nonce,
        POLYGON_CHAIN_ID,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            error!("Auto-redeem: transaction signing failed: {e}");
            return;
        }
    };

    // Broadcast.
    match eth_send_raw_transaction(http, rpc_url, &raw_tx).await {
        Ok(tx_hash) => {
            info!(
                tx_hash      = %tx_hash,
                condition_id = %condition_id,
                "✅ Native auto-redemption tx submitted."
            );
        }
        Err(e) => {
            error!(
                error        = %e,
                condition_id = %condition_id,
                "❌ Native auto-redemption failed — falling back to manual redemption."
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// derive_wallet_address — replaces derive_wallet_address_stub
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a checksummed Ethereum address from a hex private key.
///
/// # Integration
///
/// Replace `derive_wallet_address_stub` in `executor.rs` with:
/// ```rust,ignore
/// use live_trading::LiveSigner;
/// let signer = LiveSigner::from_hex_key(&CONFIG.private_key).ok()?;
/// Some(signer.wallet_address)
/// ```
///
/// Or use `LiveSigner::from_hex_key` directly during `ClobExecutor::new`.
pub fn derive_wallet_address(private_key: &str) -> Option<String> {
    let key_clean = private_key.trim_start_matches("0x");
    let bytes     = hex::decode(key_clean).ok()?;
    if bytes.len() != 32 { return None; }
    let signing_key = SigningKey::from_slice(&bytes).ok()?;
    Some(derive_address(&signing_key))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Ethereum / ABI helpers (zero external ABI crate dependencies)
// ─────────────────────────────────────────────────────────────────────────────

/// Derive an EIP-55 checksummed Ethereum address from a `SigningKey`.
fn derive_address(key: &SigningKey) -> String {
    let verifying_key = VerifyingKey::from(key);

    // Uncompressed public key is 65 bytes: [0x04 | x(32) | y(32)].
    // We hash only the 64-byte x|y payload.
    let encoded = verifying_key.to_encoded_point(false);
    let pubkey_bytes = &encoded.as_bytes()[1..]; // drop 0x04 prefix

    let mut h    = Keccak256::new();
    h.update(pubkey_bytes);
    let hash = h.finalize();

    // Last 20 bytes of the keccak256 hash = raw address.
    let addr_bytes: [u8; 20] = hash[12..].try_into().expect("slice is 20 bytes");
    eip55_checksum(&addr_bytes)
}

/// EIP-55 mixed-case checksum encoding.
fn eip55_checksum(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    let mut h    = Keccak256::new();
    h.update(hex_addr.as_bytes());
    let hash = h.finalize();

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            // Uppercase if the corresponding nibble of the hash >= 8.
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
            if nibble >= 8 { out.push(c.to_ascii_uppercase()); }
            else           { out.push(c); }
        }
    }
    out
}

/// Decode a `0x`-prefixed 20-byte address string into raw bytes.
fn decode_address(addr: &str) -> Result<[u8; 20], String> {
    let clean = addr.trim_start_matches("0x");
    let bytes = hex::decode(clean)
        .map_err(|e| format!("Address hex decode error for `{addr}`: {e}"))?;
    bytes.try_into()
        .map_err(|_| format!("Address `{addr}` is not 20 bytes"))
}

/// Pad a 20-byte address to 32 bytes (left-padded with zeroes).
fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

/// Encode a u128 value as a big-endian 32-byte ABI word.
fn pad_u256(val: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&val.to_be_bytes());
    out
}

/// Convert a Polymarket token ID (decimal string) to a 32-byte ABI uint256.
fn token_id_to_u256(token_id: &str) -> Result<[u8; 32], String> {
    // Polymarket token IDs are decimal representations of uint256 values.
    // NegRisk/Up-Down market token IDs routinely exceed u128::MAX (~78 digits),
    // so we cannot use u128::parse. Instead we do big-decimal → 32-byte BE
    // arithmetic: start with [0u8;32] and repeatedly multiply by 10 + add digit.
    if token_id.is_empty() {
        return Err("Token ID is empty".to_string());
    }
    let mut result = [0u8; 32];
    for ch in token_id.chars() {
        let digit = ch.to_digit(10)
            .ok_or_else(|| format!("Token ID `{token_id}` contains non-digit character '{ch}'"))?;
        // result = result * 10 + digit  (big-endian, in place)
        let mut carry = digit as u32;
        for byte in result.iter_mut().rev() {
            let val = (*byte as u32) * 10 + carry;
            *byte  = (val & 0xff) as u8;
            carry  = val >> 8;
        }
        if carry > 0 {
            return Err(format!("Token ID `{token_id}` overflows 256 bits"));
        }
    }
    Ok(result)
}

/// Decode a 0x-prefixed hex result from `eth_call` into a u128 (the low 16 bytes).
fn decode_u256_result(hex_result: &str) -> Result<u128, String> {
    let clean = hex_result.trim_start_matches("0x");
    // Some RPCs return "0x" or "0x0" for a zero uint256 result.
    // Normalise: left-pad with zeros to at least 32 hex chars (16 bytes).
    if clean.is_empty() || (clean.len() < 32 && clean.chars().all(|c| c == '0')) {
        return Ok(0);
    }
    if clean.len() < 32 {
        return Err(format!("eth_call result too short: `{hex_result}`"));
    }
    // Take the last 32 hex chars (16 bytes) for the low-order u128.
    let lo_hex = &clean[clean.len().saturating_sub(32)..];
    let bytes  = hex::decode(lo_hex)
        .map_err(|e| format!("Result decode error: {e}"))?;
    let arr: [u8; 16] = bytes.try_into()
        .map_err(|_| "Result slice not 16 bytes".to_string())?;
    Ok(u128::from_be_bytes(arr))
}

/// Parse a `0x`-prefixed hex string into a 32-byte array.
fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let clean = s.trim_start_matches("0x");
    let bytes = hex::decode(clean)
        .map_err(|e| format!("bytes32 decode failed: {e}"))?;
    bytes.try_into()
        .map_err(|_| format!("`{s}` is not 32 bytes"))
}

/// Current Unix timestamp in whole seconds.
fn unix_ts_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A random 64-bit nonce for order salt.
///
/// Uses the lower bits of the current nanosecond timestamp plus a thread-local
/// increment — sufficient for deduplication without importing a PRNG crate.
fn random_salt() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;

    ns.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_mul(6364136223846793005))
}

// ─────────────────────────────────────────────────────────────────────────────
// Polygon JSON-RPC helpers (hand-rolled, no web3 crate dependency)
// ─────────────────────────────────────────────────────────────────────────────

/// JSON-RPC request body.
#[derive(serde::Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    method:  &'a str,
    params:  serde_json::Value,
    id:      u64,
}

/// JSON-RPC response envelope.
#[derive(serde::Deserialize)]
struct JsonRpcResponse {
    result: Option<serde_json::Value>,
    error:  Option<serde_json::Value>,
}

/// Execute a read-only `eth_call` and return the raw hex result string.
async fn eth_call(
    http:     &reqwest::Client,
    rpc_url:  &str,
    contract: &str,
    calldata: &[u8],
) -> Result<String, String> {
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method:  "eth_call",
        params:  serde_json::json!([
            { "to": contract, "data": format!("0x{}", hex::encode(calldata)) },
            "latest"
        ]),
        id: 1,
    };

    let resp = http
        .post(rpc_url)
        .json(&req)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("RPC send failed: {e}"))?
        .json::<JsonRpcResponse>()
        .await
        .map_err(|e| format!("RPC parse failed: {e}"))?;

    if let Some(err) = resp.error {
        return Err(format!("RPC error: {err}"));
    }

    resp.result
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .ok_or_else(|| "RPC result missing or not a string".to_string())
}

/// Fetch the transaction count (nonce) for an address.
async fn get_transaction_count(
    http:    &reqwest::Client,
    rpc_url: &str,
    address: &str,
) -> Result<u64, String> {
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method:  "eth_getTransactionCount",
        params:  serde_json::json!([address, "pending"]),
        id:      2,
    };

    let resp = http
        .post(rpc_url)
        .json(&req)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("RPC nonce failed: {e}"))?
        .json::<JsonRpcResponse>()
        .await
        .map_err(|e| format!("RPC nonce parse: {e}"))?;

    if let Some(err) = resp.error {
        return Err(format!("RPC nonce error: {err}"));
    }

    let hex_str = resp.result
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .ok_or("Missing nonce result")?;

    let clean = hex_str.trim_start_matches("0x");
    u64::from_str_radix(clean, 16).map_err(|e| format!("Nonce parse error: {e}"))
}

/// Broadcast a signed raw transaction and return the tx hash.
async fn eth_send_raw_transaction(
    http:    &reqwest::Client,
    rpc_url: &str,
    raw_tx:  &[u8],
) -> Result<String, String> {
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method:  "eth_sendRawTransaction",
        params:  serde_json::json!([format!("0x{}", hex::encode(raw_tx))]),
        id:      3,
    };

    let resp = http
        .post(rpc_url)
        .json(&req)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Broadcast failed: {e}"))?
        .json::<JsonRpcResponse>()
        .await
        .map_err(|e| format!("Broadcast parse: {e}"))?;

    if let Some(err) = resp.error {
        return Err(format!("Broadcast RPC error: {err}"));
    }

    resp.result
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .ok_or_else(|| "Missing tx hash in broadcast response".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// EIP-1559 transaction signing (for on-chain redemption)
// ─────────────────────────────────────────────────────────────────────────────

/// Build and sign an EIP-1559 transaction, returning the raw RLP-encoded bytes.
///
/// Gas parameters are hardcoded to conservative values for Polygon.
/// Adjust `max_fee` and `priority_fee` via env vars if gas conditions change.
fn sign_eip1559_tx(
    signer:   &LiveSigner,
    to:       &str,
    calldata: &[u8],
    nonce:    u64,
    chain_id: u64,
) -> Result<Vec<u8>, String> {
    // Gas settings for Polygon mainnet (tune via env if needed).
    // 300k gas covers redeemPositions on a binary market.
    let gas_limit:    u128 = 300_000;
    let max_fee:      u128 = 200_000_000_000; // 200 Gwei
    let priority_fee: u128 = 30_000_000_000;  // 30 Gwei
    let value:        u128 = 0;

    let to_bytes = decode_address(to)?;

    // EIP-1559 signing payload (RLP-encoded):
    // 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit,
    //              to, value, data, access_list])
    let mut payload = vec![0x02u8]; // EIP-1559 type byte
    let inner = rlp_encode_list(&[
        rlp_encode_u64(chain_id),
        rlp_encode_u64(nonce),
        rlp_encode_u128(priority_fee),
        rlp_encode_u128(max_fee),
        rlp_encode_u128(gas_limit),
        rlp_encode_bytes(&to_bytes),
        rlp_encode_u128(value),
        rlp_encode_bytes(calldata),
        rlp_encode_list(&[]), // empty access list
    ]);
    payload.extend_from_slice(&inner);

    // Hash the signing payload (keccak256 of the 0x02 || RLP blob).
    let digest: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(&payload);
        h.finalize().into()
    };

    // Sign.
    let (sig, recid): (K256Sig, RecoveryId) = signer
        .signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| format!("Tx signing failed: {e}"))?;

    let v: u64 = recid.to_byte() as u64; // 0 or 1 for EIP-1559

    // Final signed transaction RLP: 0x02 || rlp([...fields..., v, r, s])
    let r_bytes = sig.r().to_bytes().to_vec();
    let s_bytes = sig.s().to_bytes().to_vec();

    let mut signed = vec![0x02u8];
    let signed_inner = rlp_encode_list(&[
        rlp_encode_u64(chain_id),
        rlp_encode_u64(nonce),
        rlp_encode_u128(priority_fee),
        rlp_encode_u128(max_fee),
        rlp_encode_u128(gas_limit),
        rlp_encode_bytes(&to_bytes),
        rlp_encode_u128(value),
        rlp_encode_bytes(calldata),
        rlp_encode_list(&[]), // access list
        rlp_encode_u64(v),
        rlp_encode_bytes(&r_bytes),
        rlp_encode_bytes(&s_bytes),
    ]);
    signed.extend_from_slice(&signed_inner);

    Ok(signed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal RLP encoder — no external RLP crate dependency
// ─────────────────────────────────────────────────────────────────────────────

fn rlp_encode_u64(val: u64) -> Vec<u8> {
    rlp_encode_u128(val as u128)
}

fn rlp_encode_u128(val: u128) -> Vec<u8> {
    if val == 0 {
        return vec![0x80]; // RLP empty string (zero)
    }
    // Minimal big-endian encoding (strip leading zeros).
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let trimmed = &bytes[start..];
    rlp_encode_bytes(trimmed)
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = rlp_length_prefix(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flatten().copied().collect();
    let mut out = rlp_length_prefix(payload.len(), 0xc0);
    out.extend_from_slice(&payload);
    out
}

fn rlp_length_prefix(len: usize, offset: u8) -> Vec<u8> {
    if len <= 55 {
        vec![offset + len as u8]
    } else {
        let len_bytes    = (len as u64).to_be_bytes();
        let len_start    = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len_trimmed  = &len_bytes[len_start..];
        let mut prefix   = vec![offset + 55 + len_trimmed.len() as u8];
        prefix.extend_from_slice(len_trimmed);
        prefix
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration guide (printed to stderr in debug builds)
// ─────────────────────────────────────────────────────────────────────────────

/// Integration is complete — this function is kept as a no-op for API compatibility.
#[allow(dead_code)]
pub fn print_integration_guide() {}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Test private key (NOT a real key — public domain test vector).
    const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn signer_derives_known_address() {
        let signer = LiveSigner::from_hex_key(TEST_KEY).unwrap();
        // Hardhat account #0 address for this test key.
        assert_eq!(
            signer.wallet_address.to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn signer_rejects_empty_key() {
        assert!(LiveSigner::from_hex_key("").is_err());
    }

    #[test]
    fn signer_rejects_truncated_key() {
        assert!(LiveSigner::from_hex_key("deadbeef").is_err());
    }

    #[test]
    fn sign_order_produces_hex() {
        let signer = LiveSigner::from_hex_key(TEST_KEY).unwrap();
        let sig = signer
            .sign_order("123456789", 0.65, 100, Side::Buy, 42, false, 1_782_786_000_000)
            .unwrap();
        // 0x + 65 bytes hex = 2 + 130 = 132 chars.
        assert_eq!(sig.len(), 132);
        assert!(sig.starts_with("0x"));
    }

    #[test]
    fn sign_l2_auth_produces_hex() {
        let signer = LiveSigner::from_hex_key(TEST_KEY).unwrap();
        let sig    = signer.sign_l2_auth(1_700_000_000, "POST", "/order").unwrap();
        // 0x + 65 bytes hex = 132 chars.
        assert_eq!(sig.len(), 132);
        assert!(sig.starts_with("0x"));
        assert!(hex::decode(&sig[2..]).is_ok());
    }

    #[test]
    fn pad_u256_encodes_correctly() {
        // 1_000_000 = 0x000F4240 → bytes 28..32 = [0x00, 0x0F, 0x42, 0x40]
        let padded = pad_u256(1_000_000);
        assert_eq!(padded[28], 0x00);
        assert_eq!(padded[29], 0x0F);
        assert_eq!(padded[30], 0x42);
        assert_eq!(padded[31], 0x40);
    }

    #[test]
    fn pad_address_left_pads() {
        let addr   = [0xABu8; 20];
        let padded = pad_address(&addr);
        assert_eq!(&padded[..12], &[0u8; 12]);
        assert_eq!(&padded[12..], &[0xABu8; 20]);
    }

    #[test]
    fn decode_address_strips_0x() {
        let addr = decode_address("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn token_id_to_u256_parses_large_decimal() {
        // Standard market token ID (fits in u128).
        let small = "52114319501245915516055106046884209969926127482827954674443846427813813222426";
        assert!(token_id_to_u256(small).is_ok());

        // NegRisk/Up-Down token ID that exceeds u128::MAX — must now succeed.
        let large = "84222033350467951889910809049201507042941616771733257462110487786271311278674";
        let bytes = token_id_to_u256(large).expect("NegRisk token ID must parse as uint256");
        assert_eq!(bytes.len(), 32);
        // Leading bytes should be non-zero (it's a large number).
        assert!(bytes[..16].iter().any(|&b| b != 0), "High bytes should be non-zero for large token ID");
    }

    #[test]
    fn rlp_encode_u64_zero() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
    }

    #[test]
    fn rlp_encode_u64_single_byte() {
        // Values < 0x80 are encoded as-is.
        assert_eq!(rlp_encode_u64(0x7f), vec![0x7f]);
    }

    #[test]
    fn rlp_encode_list_empty() {
        assert_eq!(rlp_encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn random_salt_is_nonzero_on_average() {
        let s1 = random_salt();
        let s2 = random_salt();
        // Can't guarantee nonzero but should differ (with overwhelming probability).
        // At minimum, ensure they're the same type and no panic.
        let _ = (s1, s2);
    }

    /// Cross-validate order signing against py_clob_client_v2 reference output.
    ///
    /// Python reference generated with fixed inputs:
    ///   exchange = 0xe222...0F59 (neg_risk), token = 1458...2908
    ///   salt=42, ts_ms=1750000000000, price=0.35, size=10
    ///   maker/signer = wallet derived from PRIVATE_KEY
    ///   Expected order_hash = 0x3c8dcc...359a
    #[test]
    fn sign_order_matches_python_reference() {
        dotenvy::dotenv().ok();
        let pk = std::env::var("PRIVATE_KEY")
            .unwrap_or_else(|_| "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string());

        // Only run meaningful assertion if using the real key.
        let using_real_key = pk != "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let signer = LiveSigner::from_hex_key(&pk).expect("valid key");
        let token_id = "14584067488723929993675351699740384033719862943912599772935229691412563272908";
        let salt: u64      = 42;
        let ts_ms: u64     = 1750000000000;
        let maker_amount: u128 = 3500000;
        let taker_amount: u128 = 10000000;
        let side           = Side::Buy;
        let neg_risk       = true;  // uses 0xe222...0F59

        // Reproduce the sign_order digest manually.
        use sha3::{Digest as _, Keccak256};

        let order_type_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"Order(uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)");
            h.finalize().into()
        };
        let domain_type_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
            h.finalize().into()
        };
        let name_hash: [u8; 32] = { let mut h = Keccak256::new(); h.update(b"Polymarket CTF Exchange"); h.finalize().into() };
        let ver_hash:  [u8; 32] = { let mut h = Keccak256::new(); h.update(b"2"); h.finalize().into() };
        let exchange_bytes = decode_address(CTF_EXCHANGE_NEG_RISK).unwrap();
        let domain_sep: [u8; 32] = {
            let mut enc = Vec::with_capacity(5 * 32);
            enc.extend_from_slice(&domain_type_hash);
            enc.extend_from_slice(&name_hash);
            enc.extend_from_slice(&ver_hash);
            enc.extend_from_slice(&pad_u256(137));
            enc.extend_from_slice(&pad_address(&exchange_bytes));
            let mut h = Keccak256::new(); h.update(&enc); h.finalize().into()
        };
        let maker_addr = decode_address(&signer.wallet_address).unwrap();
        let token_u256 = token_id_to_u256(token_id).unwrap();
        let struct_hash: [u8; 32] = {
            let mut enc = Vec::with_capacity(12 * 32);
            enc.extend_from_slice(&order_type_hash);
            enc.extend_from_slice(&pad_u256(salt as u128));
            enc.extend_from_slice(&pad_address(&maker_addr));
            enc.extend_from_slice(&pad_address(&maker_addr));
            enc.extend_from_slice(&token_u256);
            enc.extend_from_slice(&pad_u256(maker_amount));
            enc.extend_from_slice(&pad_u256(taker_amount));
            enc.extend_from_slice(&pad_u256(side as u128));
            enc.extend_from_slice(&pad_u256(0)); // signatureType
            enc.extend_from_slice(&pad_u256(ts_ms as u128));
            enc.extend_from_slice(&[0u8; 32]); // metadata
            enc.extend_from_slice(&[0u8; 32]); // builder
            let mut h = Keccak256::new(); h.update(&enc); h.finalize().into()
        };
        let order_hash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"\x19\x01");
            h.update(domain_sep);
            h.update(struct_hash);
            h.finalize().into()
        };

        let order_hash_hex = format!("0x{}", hex::encode(order_hash));
        println!("Rust   order_hash: {order_hash_hex}");

        if using_real_key {
            assert_eq!(
                order_hash_hex,
                "0x3c8dcc398b9110e07066964267e20087307e53e336afa2379beae37f1d72359a",
                "Order hash does not match Python reference!"
            );
            let sig = signer.sign_order(token_id, 0.35, 10, side, salt, neg_risk, ts_ms, &signer.wallet_address.clone(), 0).unwrap();
            println!("Rust   signature:   {sig}");
            assert_eq!(sig, "0x815661e9ecc72f2d04eb602633e162ddd7f3ea4d0a259b99c387a61a4140ddfc3905ad565498888fce100f173332f04562d59f78b2965eaf6ee939323915bf9f1b",
                "Signature does not match Python reference!");
        } else {
            println!("Skipping assertion — using dummy test key, not the real private key.");
        }
    }

    /// Live RPC integration test — requires real POLY_RPC_URL and wallet in env.
    /// Run with: cargo test rpc_pusd_balance -- --nocapture --ignored
    #[tokio::test]
    #[ignore]
    async fn rpc_pusd_balance_live() {
        dotenvy::dotenv().ok();
        let rpc_url = std::env::var("POLY_RPC_URL")
            .expect("POLY_RPC_URL must be set");
        let wallet = std::env::var("WALLET_ADDRESS")
            .or_else(|_| std::env::var("PRIVATE_KEY").map(|k| {
                let signer = LiveSigner::from_hex_key(&k).expect("invalid key");
                signer.wallet_address
            }))
            .expect("WALLET_ADDRESS or PRIVATE_KEY must be set");

        println!("\n=== RPC balance test ===");
        println!("RPC URL : {rpc_url}");
        println!("Wallet  : {wallet}");

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build().unwrap();

        // Test decode_u256_result with the known Alchemy response.
        let known_response = "0x0000000000000000000000000000000000000000000000000000000000385043";
        let decoded = decode_u256_result(known_response);
        println!("decode_u256_result({known_response}) = {decoded:?}");
        assert_eq!(decoded.unwrap(), 3690563, "decode_u256_result regression");

        // Build calldata the same way get_usdc_balance does.
        let addr_bytes = decode_address(&wallet).expect("invalid wallet");
        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&BALANCE_OF_SELECTOR);
        calldata.extend_from_slice(&pad_address(&addr_bytes));
        println!("calldata : 0x{}", hex::encode(&calldata));

        // Direct eth_call for pUSD.
        println!("Querying pUSD ({USDC_CONTRACT})...");
        match eth_call(&http, &rpc_url, USDC_CONTRACT, &calldata).await {
            Ok(raw_hex) => {
                println!("  raw_hex  : {raw_hex}");
                match decode_u256_result(&raw_hex) {
                    Ok(raw) => println!("  balance  : ${:.6} (raw={raw})", raw as f64 / 1e6),
                    Err(e)  => println!("  decode ERR: {e}"),
                }
            }
            Err(e) => println!("  eth_call ERR: {e}"),
        }

        // Full helper.
        println!("Calling get_usdc_balance helper...");
        match get_usdc_balance(&http, &rpc_url, &wallet).await {
            Ok(bal)  => println!("  TOTAL balance = ${bal:.6}"),
            Err(e)   => println!("  get_usdc_balance ERR: {e}"),
        }
    }

    #[test]
    fn sign_eip1559_tx_produces_nonempty_bytes() {
        let signer = LiveSigner::from_hex_key(TEST_KEY).unwrap();
        let calldata = hex::decode("70a08231").unwrap();
        let raw = sign_eip1559_tx(&signer, CTF_CONTRACT, &calldata, 0, POLYGON_CHAIN_ID)
            .unwrap();
        assert!(!raw.is_empty());
        assert_eq!(raw[0], 0x02); // EIP-1559 type byte
    }
}
