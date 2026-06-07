//! Bot Detector
//!
//! Unified bot detection interface.
//!
//! ## Detection Layers
//!
//! 1. **Fingerprint Analysis**: User-Agent, headers, TLS fingerprints
//! 2. **IP Reputation**: Known bots, TOR, VPN, proxy detection
//! 3. **Behavioral Analysis**: Request patterns, rate anomalies
//! 4. **Challenges**: JavaScript challenges for suspicious clients
//!
//! ## Scoring System
//!
//! Bot detection uses a weighted scoring system:
//! - Score 0-30: Allow (normal traffic)
//! - Score 30-70: Challenge (suspicious)
//! - Score 70+: Block (likely bot)
//!
//! ## Configuration
//!
//! - `challenge_threshold`: Score to trigger challenge
//! - `block_threshold`: Score to block immediately
//! - `allow_known_bots`: Allow verified crawlers (Googlebot, etc.)
//! - `block_tor`: Block known TOR exit nodes
//! - `block_vpn`: Block known VPN providers
//!
//! ## Usage
//!
//! ```rust
//! use waf_bot_detector::{BotDetector, BotDetectorConfig};
//!
//! let config = BotDetectorConfig {
//!     enabled: true,
//!     challenge_threshold: 30,
//!     block_threshold: 70,
//!     allow_known_bots: true,
//!     block_tor: true,
//!     ..Default::default()
//! };
//!
//! let detector = BotDetector::new(config);
//! let result = detector.detect(&request_context);
//! ```

use super::{
    BotAnalysisResult, ChallengeGenerator, ClientFingerprint, FingerprintCollector,
    ReputationDatabase,
};
use waf_common::*;

/// Bot detection result
#[derive(Debug, Clone)]
pub struct BotDetectionResult {
    pub is_bot: bool,
    pub confidence: f32,
    pub score: i32,
    pub indicators: Vec<String>,
    pub recommended_action: Action,
    pub should_challenge: bool,
}

impl Default for BotDetectionResult {
    fn default() -> Self {
        Self {
            is_bot: false,
            confidence: 0.0,
            score: 0,
            indicators: Vec::new(),
            recommended_action: Action::Allow,
            should_challenge: false,
        }
    }
}

/// Bot detection configuration
#[derive(Debug, Clone)]
pub struct BotDetectorConfig {
    pub enabled: bool,
    pub challenge_threshold: i32,
    pub block_threshold: i32,
    pub allow_known_bots: bool,
    pub block_tor: bool,
    pub block_vpn: bool,
}

impl Default for BotDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            challenge_threshold: 30,
            block_threshold: 70,
            allow_known_bots: true,
            block_tor: true,
            block_vpn: false,
        }
    }
}

/// Bot detector
pub struct BotDetector {
    fingerprint_collector: FingerprintCollector,
    reputation_db: ReputationDatabase,
    challenge_generator: ChallengeGenerator,
    config: BotDetectorConfig,
}

impl BotDetector {
    /// Create a new bot detector
    pub fn new(config: BotDetectorConfig) -> Self {
        Self {
            fingerprint_collector: FingerprintCollector::new(),
            reputation_db: ReputationDatabase::new(),
            challenge_generator: ChallengeGenerator::new(),
            config,
        }
    }

    /// Detect if a request is from a bot
    pub fn detect(&self, ctx: &RequestContext) -> BotDetectionResult {
        if !self.config.enabled {
            return BotDetectionResult::default();
        }

        let mut result = BotDetectionResult::default();

        // Collect fingerprint
        let fp = self.fingerprint_collector.collect_from_request(ctx);

        // Check for known bots first
        if self.config.allow_known_bots && fp.is_known_bot {
            result.is_bot = false;
            result.confidence = 1.0;
            result
                .indicators
                .push(format!("Known bot: {}", fp.bot_name.unwrap_or_default()));
            return result;
        }

        // Check IP reputation
        if let Some(rep) = self.reputation_db.get_reputation(&ctx.client_ip) {
            if self.config.block_tor && rep.category == super::reputation::ReputationCategory::Tor {
                result.indicators.push("TOR exit node".to_string());
                result.score += 100;
            }
            if self.config.block_vpn && rep.category == super::reputation::ReputationCategory::Vpn {
                result.indicators.push("VPN provider".to_string());
                result.score += 50;
            }
            result.score += rep.score as i32 / 2;
        }

        // Analyze fingerprint
        let analysis = self.fingerprint_collector.analyze(&fp);
        result.score += analysis.score;
        result.indicators.extend(analysis.indicators);

        // Determine bot status
        result.is_bot = result.score >= self.config.block_threshold;
        result.confidence = (result.score as f32 / 100.0).min(1.0);

        // Determine action
        if result.score >= self.config.block_threshold {
            result.recommended_action = Action::Block {
                status_code: 403,
                body: "Access denied - bot detected".to_string(),
                reason: format!("Bot detected with score {}", result.score),
            };
        } else if result.score >= self.config.challenge_threshold {
            result.should_challenge = true;
            result.recommended_action = Action::Challenge {
                challenge_type: ChallengeType::Javascript,
                timeout: 300,
            };
        }

        result
    }

    /// Generate a challenge for a request
    pub async fn generate_challenge(&self, ctx: &RequestContext) -> String {
        let challenge_id = self
            .challenge_generator
            .generate_challenge(&ctx.client_ip)
            .await;
        self.challenge_generator
            .generate_challenge_page(&challenge_id)
    }

    /// Validate a challenge response
    pub async fn validate_challenge(
        &self,
        client_ip: &str,
        signals: crate::challenge::FingerprintSignals,
        pow_nonce: u64,
        challenge_id: &str,
    ) -> std::result::Result<bool, waf_common::WafError> {
        self.challenge_generator
            .validate_response(client_ip, signals, pow_nonce, challenge_id)
            .await
    }

    /// Check if client passed challenge
    pub async fn is_challenge_passed(&self, client_ip: &str) -> bool {
        self.challenge_generator.has_valid_token(client_ip).await
    }

    /// Update IP reputation
    pub fn update_ip_reputation(&self, ip: &str, attack: bool) {
        let delta = if attack { 20 } else { -5 };
        let category = if attack {
            super::reputation::ReputationCategory::Suspicious
        } else {
            super::reputation::ReputationCategory::Clean
        };
        self.reputation_db.update_reputation(ip, delta, category);
    }

    /// Add TOR node to blocklist
    pub fn add_tor_node(&self, ip: &str) {
        self.reputation_db.add_tor_node(ip);
    }

    /// Add VPN range to blocklist
    pub fn add_vpn_range(&self, range: &str) {
        self.reputation_db.add_vpn_range(range);
    }
}

impl Default for BotDetector {
    fn default() -> Self {
        Self::new(BotDetectorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> RequestContext {
        RequestContext {
            id: "test-123".to_string(),
            method: HttpMethod::Get,
            uri: "/".to_string(),
            query_string: String::new(),
            headers: vec![("User-Agent".to_string(), "Mozilla/5.0".to_string())],
            client_ip: "192.168.1.1".to_string(),
            body: None,
            content_type: None,
            timestamp: chrono::Utc::now(),
            tls: None,
            rate_limit_info: None,
        }
    }

    #[test]
    fn test_known_bot_allowed() {
        let detector = BotDetector::new(BotDetectorConfig {
            allow_known_bots: true,
            ..Default::default()
        });

        let mut ctx = create_test_context();
        ctx.headers[0].1 = "Googlebot/2.1".to_string();

        let result = detector.detect(&ctx);
        assert!(!result.is_bot);
    }

    #[test]
    fn test_empty_user_agent_flagged() {
        let detector = BotDetector::default();

        let mut ctx = create_test_context();
        ctx.headers[0].1 = "".to_string();

        let result = detector.detect(&ctx);
        assert!(result.score > 0);
    }
}
