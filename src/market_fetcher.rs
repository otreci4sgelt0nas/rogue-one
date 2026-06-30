//! market_fetcher.rs — Polymarket Gamma API client.
//!
//! Resolves the active binary market for the configured asset and window,
//! returning a fully-populated [`MarketInfo`] ready to publish into [`SharedState`].
//!
//! # Slug construction (mirrors Python MarketFetcher)
//!
//! ```text
//! window_ts   = (now_unix // window_secs) * window_secs
//! expiry_ts   = window_ts + window_secs
//! slug        = "{asset}-updown-{window}m-{window_ts}"
//! slug_btc_fb = "bitcoin-updown-{window}m-{window_ts}"   (BTC only fallback)
//! ```
//!
//! # Hot-path isolation
//!
//! This module is **never called on the WebSocket tick path**. It is called:
//! 1. Once at startup by `SniperBrain::start`.
//! 2. Once per rollover (every `MARKET_WINDOW` minutes) by `handle_rollover`.
//!
//! Allocations, `String` formatting, and HTTP round-trips are all acceptable here.

use std::sync::Arc;

use reqwest::Client;
use serde::Deserialize;
use tracing::{info, warn};

use crate::errors::{FetchResult, MarketFetcherError};
use crate::state::MarketInfo;
use crate::config::CONFIG;

// ─────────────────────────────────────────────────────────────────────────────
// Gamma API response shapes
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level event returned by the Gamma API `/events?slug=...` endpoint.
#[derive(Debug, Deserialize)]
struct GammaEvent {
    slug: Option<String>,
    markets: Option<Vec<GammaMarket>>,
}

/// A single market nested inside a [`GammaEvent`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GammaMarket {
    id: Option<String>,

    /// JSON-encoded array of CLOB token IDs, e.g. `"[\"0xabc...\",\"0xdef...\"]"` .
    clob_token_ids: Option<String>,

    /// Outcome labels — the Gamma API returns this as either a proper JSON array
    /// `["Up", "Down"]` OR as a JSON-encoded string `"[\"Up\", \"Down\"]"`,
    /// so we use a custom deserialiser that handles both forms.
    #[serde(default, deserialize_with = "deser_string_or_vec::deserialize")]
    outcomes: Option<Vec<String>>,

    /// UMA condition ID used for on-chain redemption after settlement.
    condition_id: Option<String>,

    /// Whether this is a NegRisk market.
    #[serde(default)]
    neg_risk: Option<bool>,
}

/// Custom Serde deserialiser: accepts both a native JSON string-array
/// `["Up", "Down"]` **and** a JSON-encoded string `"[\"Up\", \"Down\"]"`,
/// returning `Option<Vec<String>>` in both cases.
///
/// The Polymarket Gamma API has historically returned `outcomes` as a
/// JSON-encoded string rather than a proper array. Using `serde_json::Value`
/// as an intermediate avoids a hard type-mismatch error that would otherwise
/// silently treat the whole market as "not found".
mod deser_string_or_vec {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(de: D) -> Result<Option<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_json::Value> = Option::deserialize(de)?;
        Ok(match opt {
            None => None,
            Some(serde_json::Value::Array(arr)) => Some(
                arr.into_iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
            ),
            Some(serde_json::Value::String(s)) => {
                // E.g. "[\"Up\", \"Down\"]" — parse inner JSON.
                Some(serde_json::from_str::<Vec<String>>(&s).unwrap_or_default())
            }
            _ => None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MarketFetcher
// ─────────────────────────────────────────────────────────────────────────────

/// Stateless HTTP client that resolves Polymarket binary markets by slug.
///
/// Wrap in `Arc<MarketFetcher>` to share across the rollover task and startup.
/// All methods take `&self` — there is no mutable state; the resolved
/// [`MarketInfo`] is returned by value for the caller to publish via
/// [`crate::state::SharedState::publish_market`].
#[derive(Debug)]
pub struct MarketFetcher {
    /// Shared reqwest client (keeps the connection pool alive across calls).
    client: Client,

    /// Base URL for the Gamma events API.
    gamma_api_url: &'static str,
}

impl MarketFetcher {
    /// Construct a new `MarketFetcher` with a dedicated HTTP client.
    ///
    /// The client is configured with:
    /// - `rustls` TLS (no OpenSSL dependency on aarch64).
    /// - A 10-second connection timeout.
    /// - A 15-second total request timeout.
    /// - `gzip` decompression (matches `reqwest` feature flag in `Cargo.toml`).
    pub fn new() -> Arc<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(10))
            .gzip(true)
            .user_agent("sniper-bot/0.1")
            .build()
            .expect("Failed to build reqwest client for MarketFetcher");

        Arc::new(Self {
            client,
            gamma_api_url: "https://gamma-api.polymarket.com/events",
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /// Resolve the current active market and return a [`MarketInfo`].
    ///
    /// Calculates the active window timestamp deterministically from the wall
    /// clock, constructs the primary and optional fallback slugs, then makes
    /// up to two HTTP calls (primary → fallback).
    ///
    /// # Arguments
    /// - `rollover`: if `true`, logs additional context (used by `handle_rollover`).
    ///
    /// # Errors
    /// Returns [`MarketFetcherError`] if:
    /// - Both primary and fallback slugs return no event.
    /// - The market's `clobTokenIds` cannot be parsed.
    /// - The HTTP call fails (network, TLS, timeout).
    pub async fn update_market(&self, rollover: bool) -> FetchResult<MarketInfo> {
        let window_secs = CONFIG.market_window_sec();
        let asset       = &CONFIG.market_asset;

        // ── Deterministic window calculation ──────────────────────────────────
        let now_secs    = crate::state::unix_now_secs() as u64;
        let window_ts   = (now_secs / window_secs) * window_secs;
        let expiry_ts   = window_ts + window_secs;

        let start_human = chrono::DateTime::from_timestamp(window_ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| window_ts.to_string());

        let verb = if rollover { "ROLLOVER: targeting" } else { "targeting" };
        info!(
            "🎯 SNIPER SCOPE: {} ACTIVE {}m window starting at {}",
            verb, CONFIG.market_window_min, start_human
        );

        // ── Slug construction ─────────────────────────────────────────────────
        let slug_primary = format!(
            "{}-updown-{}m-{}",
            asset, CONFIG.market_window_min, window_ts
        );
        let slug_fallback: Option<String> = if asset == "btc" {
            Some(format!("bitcoin-updown-{}m-{}", CONFIG.market_window_min, window_ts))
        } else {
            None
        };

        // ── HTTP fetch with fallback ──────────────────────────────────────────
        let event = self.fetch_event_by_slug(&slug_primary).await;

        let (event, slug_used) = match event {
            Ok(Some(e)) => (e, slug_primary.clone()),
            Ok(None) | Err(_) => {
                if let Some(ref fb) = slug_fallback {
                    warn!(
                        "Primary slug `{}` not found — trying fallback `{}`",
                        slug_primary, fb
                    );
                    match self.fetch_event_by_slug(fb).await? {
                        Some(e) => (e, fb.clone()),
                        None => {
                            let slugs = [slug_primary, slug_fallback.unwrap_or_default()].to_vec();
                            return Err(MarketFetcherError::NotFound { window_ts, slugs });
                        }
                    }
                } else {
                    return Err(MarketFetcherError::NotFound {
                        window_ts,
                        slugs: vec![slug_primary],
                    });
                }
            }
        };

        // ── Extract market and token IDs ──────────────────────────────────────
        let market_slug = event.slug.unwrap_or(slug_used);
        let market = event
            .markets
            .as_deref()
            .and_then(|ms| ms.first())
            .ok_or_else(|| MarketFetcherError::TokenIdExtraction {
                market_id: market_slug.clone(),
                reason: "event has no nested markets".into(),
            })?;

        let market_id = market.id.clone().unwrap_or_default();
        let condition_id = market.condition_id.clone().unwrap_or_default();
        let neg_risk = market.neg_risk.unwrap_or(false);

        let (token_id_up, token_id_down) = self
            .extract_token_ids(market, &market_id)
            .map_err(|reason| MarketFetcherError::TokenIdExtraction {
                market_id: market_id.clone(),
                reason,
            })?;

        info!(
            token_up   = %token_id_up,
            token_down = %token_id_down,
            market_id  = %market_id,
            slug       = %market_slug,
            expiry_ts  = expiry_ts,
            "✅ Deterministic market synced!"
        );

        Ok(MarketInfo {
            token_id_up,
            token_id_down,
            market_id,
            market_slug,
            condition_id,
            expiry_ts,
            neg_risk,
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Make a single GET request to the Gamma API for the given slug.
    ///
    /// Returns `Ok(Some(event))` if found, `Ok(None)` if the API returns an
    /// empty array or 404, or `Err` on network/parse failure.
    async fn fetch_event_by_slug(&self, slug: &str) -> FetchResult<Option<GammaEvent>> {
        info!("Fetching Gamma API for slug: `{}`", slug);

        let response = self
            .client
            .get(self.gamma_api_url)
            .query(&[("slug", slug)])
            .send()
            .await?;

        let status = response.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(MarketFetcherError::ApiStatus {
                status,
                slug: slug.to_string(),
            });
        }

        // Parse the response body as a JSON array of events.
        let body = response.text().await?;
        let events: Vec<GammaEvent> =
            serde_json::from_str(&body).map_err(|e| MarketFetcherError::Deserialise { source: e })?;

        Ok(events.into_iter().next())
    }

    /// Extract `(token_id_up, token_id_down)` from a [`GammaMarket`] using
    /// outcome-name matching with index-based fallback.
    ///
    /// Mirrors the Python logic exactly:
    /// 1. Try to find "Up"/"Yes" and "Down"/"No" by name in `outcomes`.
    /// 2. If name matching fails, fall back to index 0 = up, 1 = down.
    ///
    /// Returns `Err(String)` with a human-readable reason on failure.
    fn extract_token_ids(
        &self,
        market: &GammaMarket,
        market_id: &str,
    ) -> Result<(String, String), String> {
        // Parse the embedded JSON string that Gamma wraps token IDs in.
        let ids_json = market
            .clob_token_ids
            .as_deref()
            .unwrap_or("[]");

        let token_ids: Vec<String> = serde_json::from_str(ids_json)
            .map_err(|e| format!("clobTokenIds JSON parse error: {e}"))?;

        if token_ids.len() < 2 {
            return Err(format!(
                "clobTokenIds has {} entries (need ≥ 2)",
                token_ids.len()
            ));
        }

        // ── Outcome-name matching ─────────────────────────────────────────────
        let outcomes = market.outcomes.as_deref().unwrap_or(&[]);

        let up_idx = outcomes
            .iter()
            .position(|o| o == "Up" || o == "Yes");
        let down_idx = outcomes
            .iter()
            .position(|o| o == "Down" || o == "No");

        match (up_idx, down_idx) {
            (Some(ui), Some(di))
                if ui < token_ids.len() && di < token_ids.len() =>
            {
                info!("Extracted token IDs via outcome name matching.");
                Ok((token_ids[ui].clone(), token_ids[di].clone()))
            }
            _ => {
                // ── Index fallback ────────────────────────────────────────────
                warn!(
                    market_id = %market_id,
                    "Outcome name matching failed — falling back to token index 0/1."
                );
                Ok((token_ids[0].clone(), token_ids[1].clone()))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_token_ids_by_name_up_down() {
        let fetcher = MarketFetcher::new();
        let market = GammaMarket {
            id: Some("1".into()),
            clob_token_ids: Some(r#"["tok_up","tok_down"]"#.into()),
            outcomes: Some(vec!["Up".into(), "Down".into()]),
            condition_id: None,
            neg_risk: None,
        };
        let (up, down) = fetcher.extract_token_ids(&market, "test_market").unwrap();
        assert_eq!(up,   "tok_up");
        assert_eq!(down, "tok_down");
    }

    #[test]
    fn extract_token_ids_by_name_yes_no() {
        let fetcher = MarketFetcher::new();
        let market = GammaMarket {
            id: Some("2".into()),
            clob_token_ids: Some(r#"["tok_yes","tok_no"]"#.into()),
            outcomes: Some(vec!["Yes".into(), "No".into()]),
            condition_id: None,
            neg_risk: None,
        };
        let (up, down) = fetcher.extract_token_ids(&market, "test_market").unwrap();
        assert_eq!(up,   "tok_yes");
        assert_eq!(down, "tok_no");
    }

    #[test]
    fn extract_token_ids_fallback_to_index() {
        let fetcher = MarketFetcher::new();
        // No recognised outcome labels → fall back to index 0/1
        let market = GammaMarket {
            id: Some("3".into()),
            clob_token_ids: Some(r#"["tok_0","tok_1"]"#.into()),
            outcomes: Some(vec!["Weird".into(), "Labels".into()]),
            condition_id: None,
            neg_risk: None,
        };
        let (up, down) = fetcher.extract_token_ids(&market, "test_market").unwrap();
        assert_eq!(up,   "tok_0");
        assert_eq!(down, "tok_1");
    }

    #[test]
    fn extract_token_ids_errors_on_empty_array() {
        let fetcher = MarketFetcher::new();
        let market = GammaMarket {
            id: Some("4".into()),
            clob_token_ids: Some("[]".into()),
            outcomes: Some(vec![]),
            condition_id: None,
            neg_risk: None,
        };
        assert!(fetcher.extract_token_ids(&market, "test_market").is_err());
    }

    #[test]
    fn extract_token_ids_errors_on_bad_json() {
        let fetcher = MarketFetcher::new();
        let market = GammaMarket {
            id: Some("5".into()),
            clob_token_ids: Some("not json".into()),
            outcomes: None,
            condition_id: None,
            neg_risk: None,
        };
        assert!(fetcher.extract_token_ids(&market, "test_market").is_err());
    }

    #[test]
    fn extract_token_ids_reversed_outcome_order() {
        // Outcomes are in Down/Up order — name matching should still find them.
        let fetcher = MarketFetcher::new();
        let market = GammaMarket {
            id: Some("6".into()),
            clob_token_ids: Some(r#"["tok_down","tok_up"]"#.into()),
            outcomes: Some(vec!["Down".into(), "Up".into()]),
            condition_id: None,
            neg_risk: None,
        };
        let (up, down) = fetcher.extract_token_ids(&market, "test_market").unwrap();
        // Up outcome is at index 1, Down at index 0
        assert_eq!(up,   "tok_up");
        assert_eq!(down, "tok_down");
    }
}
