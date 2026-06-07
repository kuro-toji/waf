//! Custom JavaScript Challenge System
//!
//! Implements browser verification challenges without external services.
//! Collects fingerprint signals and issues tokens for verified browsers.
//!
//! ## Challenge Flow
//!
//! ```text
//! Request → Challenge Page (HTML+JS) → Client Executes JS → Fingerprint Collected
//!                                    ↓
//!                         Proof-of-Work Computed
//!                                    ↓
//!                          Token Issued → Request with Token
//! ```
//!
//! ## Signals Collected
//!
//! - Canvas fingerprint (browser-specific rendering)
//! - WebGL vendor/renderer (GPU fingerprint)
//! - Navigator properties (hardwareConcurrency, deviceMemory)
//! - Screen dimensions and color depth
//! - Timing variance (bots have low variance)
//! - Proof-of-work solution

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use waf_common::WafError;

/// Challenge token issued to verified browsers
#[derive(Debug, Clone)]
pub struct ChallengeToken {
    /// Unique token ID
    pub token_id: String,
    /// Client IP that solved the challenge
    pub client_ip: String,
    /// When the token was issued
    pub issued_at: DateTime<Utc>,
    /// When the token expires
    pub expires_at: DateTime<Utc>,
    /// Fingerprint score from collected signals
    pub fingerprint_score: u8,
    /// Proof-of-work difficulty used
    pub pow_difficulty: u32,
    /// Whether the challenge was successfully solved
    pub solved: bool,
}

impl ChallengeToken {
    /// Check if token is still valid
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.solved
    }

    /// Check if token has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Create a new token
    pub fn new(
        token_id: String,
        client_ip: String,
        fingerprint_score: u8,
        pow_difficulty: u32,
        timeout_secs: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            token_id,
            client_ip,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(timeout_secs as i64),
            fingerprint_score,
            pow_difficulty,
            solved: false,
        }
    }

    /// Mark token as solved
    pub fn mark_solved(&mut self) {
        self.solved = true;
    }
}

/// Fingerprint signals collected from client
#[derive(Debug, Clone, Default)]
pub struct FingerprintSignals {
    /// Canvas fingerprint hash
    pub canvas_hash: Option<String>,
    /// WebGL vendor string
    pub webgl_vendor: Option<String>,
    /// WebGL renderer string
    pub webgl_renderer: Option<String>,
    /// Hardware concurrency (CPU cores)
    pub hardware_concurrency: Option<u32>,
    /// Device memory in GB
    pub device_memory: Option<f32>,
    /// Screen width
    pub screen_width: Option<u32>,
    /// Screen height
    pub screen_height: Option<u32>,
    /// Screen color depth
    pub color_depth: Option<u32>,
    /// Timing variance (low = bot)
    pub timing_variance: Option<f64>,
    /// Proof-of-work nonce
    pub pow_nonce: Option<u64>,
    /// Proof-of-work solution valid
    pub pow_valid: bool,
}

impl FingerprintSignals {
    /// Calculate a fingerprint score based on signals (0-100)
    /// Higher score = more likely to be legitimate browser
    pub fn calculate_score(&self) -> u8 {
        let mut score: u32 = 50; // Start neutral

        // Canvas fingerprint indicates real browser
        if self.canvas_hash.is_some() && !self.canvas_hash.as_ref().unwrap().is_empty() {
            score += 15;
        }

        // WebGL indicates real browser (headless often lacks WebGL)
        if self.webgl_vendor.is_some() && self.webgl_renderer.is_some() {
            score += 15;
            // Check for known headless indicators
            let renderer = self.webgl_renderer.as_ref().unwrap().to_lowercase();
            if renderer.contains("swiftshader") || renderer.contains("llvmpipe") {
                score -= 20; // Known software renderer
            }
        }

        // Reasonable hardware concurrency
        if let Some(hw) = self.hardware_concurrency {
            if hw >= 2 && hw <= 64 {
                score += 5;
            } else if hw > 64 {
                score -= 10; // Likely spoofed
            }
        }

        // Reasonable device memory
        if let Some(mem) = self.device_memory {
            if mem >= 1.0 && mem <= 32.0 {
                score += 5;
            }
        }

        // Screen dimensions
        if let (Some(w), Some(h)) = (self.screen_width, self.screen_height) {
            if w >= 800 && h >= 600 && w <= 7680 && h <= 4320 {
                score += 5;
            }
        }

        // Timing variance indicates human-like behavior
        if let Some(var) = self.timing_variance {
            if var > 0.1 && var < 1000.0 {
                score += 10;
            } else if var <= 0.1 {
                score -= 15; // Too uniform = bot
            }
        }

        // Proof-of-work verified
        if self.pow_valid {
            score += 5;
        }

        // Clamp to 0-100
        score.max(0).min(100) as u8
    }

    /// Check for headless browser indicators
    pub fn is_headless(&self) -> bool {
        // Check WebGL renderer for software rendering
        if let Some(renderer) = &self.webgl_renderer {
            let r = renderer.to_lowercase();
            if r.contains("swiftshader") || r.contains("llvmpipe") || r.contains("mesa") {
                return true;
            }
        }

        // Very low timing variance
        if let Some(var) = self.timing_variance {
            if var < 0.05 {
                return true;
            }
        }

        // Missing canvas
        if self.canvas_hash.is_none() || self.canvas_hash.as_ref().unwrap().is_empty() {
            return true;
        }

        false
    }
}

/// Challenge generator for browser verification
pub struct ChallengeGenerator {
    /// Active challenges by client IP
    challenges: Arc<RwLock<HashMap<String, ChallengeToken>>>,
    /// Proof-of-work difficulty (leading zeros required)
    pow_difficulty: u32,
    /// Challenge timeout in seconds
    challenge_timeout_secs: u64,
    /// Token timeout in seconds (after solving)
    token_timeout_secs: u64,
}

impl ChallengeGenerator {
    /// Create a new challenge generator
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            pow_difficulty: 16, // 16 leading zero bits = ~65536 attempts avg
            challenge_timeout_secs: 60,
            token_timeout_secs: 3600, // 1 hour
        }
    }

    /// Create with custom configuration
    pub fn with_config(pow_difficulty: u32, challenge_timeout: u64, token_timeout: u64) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            pow_difficulty,
            challenge_timeout_secs: challenge_timeout,
            token_timeout_secs: token_timeout,
        }
    }

    /// Generate a new challenge for a client
    pub async fn generate_challenge(&self, client_ip: &str) -> String {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        
        let token = ChallengeToken::new(
            challenge_id.clone(),
            client_ip.to_string(),
            0, // Score computed after solution
            self.pow_difficulty,
            self.challenge_timeout_secs,
        );

        self.challenges.write().await.insert(client_ip.to_string(), token);
        challenge_id
    }

    /// Generate the challenge HTML page with embedded JavaScript
    pub fn generate_challenge_page(&self, challenge_id: &str) -> String {
        let pow_difficulty = self.pow_difficulty;

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            text-align: center;
            max-width: 400px;
        }}
        h1 {{ color: #1f2937; margin-bottom: 16px; font-size: 24px; }}
        p {{ color: #6b7280; margin-bottom: 24px; line-height: 1.6; }}
        .spinner {{
            width: 40px; height: 40px;
            border: 3px solid #e5e7eb;
            border-top-color: #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        .status {{
            font-size: 14px;
            color: #9ca3af;
        }}
        .error {{
            color: #dc2626;
            background: #fef2f2;
            padding: 12px;
            border-radius: 8px;
            margin-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Verification</h1>
        <div class="spinner"></div>
        <p>Please wait while we verify your browser...</p>
        <div class="status" id="status">Collecting browser signals...</div>
        <div id="error"></div>
    </div>

    <script>
    (async function() {{
        const challengeId = '{challenge_id}';
        const powDifficulty = {pow_difficulty};
        const statusEl = document.getElementById('status');
        const errorEl = document.getElementById('error');

        try {{
            // Collect fingerprint signals
            statusEl.textContent = 'Collecting fingerprint...';
            const signals = await collectSignals();

            // Compute proof-of-work
            statusEl.textContent = 'Computing verification...';
            const powNonce = await computeProofOfWork(challengeId, powDifficulty);

            // Send results to server
            statusEl.textContent = 'Verifying...';
            const response = await fetch('/_waf_challenge_verify', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    challengeId,
                    signals,
                    powNonce
                }})
            }});

            const result = await response.json();

            if (result.success) {{
                // Challenge passed - reload original request
                statusEl.textContent = 'Verified!';
                statusEl.style.color = '#059669';
                setTimeout(() => window.location.reload(), 500);
            }} else {{
                errorEl.textContent = result.error || 'Verification failed';
                errorEl.className = 'error';
            }}
        }} catch (err) {{
            errorEl.textContent = 'Error: ' + err.message;
            errorEl.className = 'error';
        }}
    }})();

    async function collectSignals() {{
        const signals = {{}};

        // Canvas fingerprint
        try {{
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = \"14px 'Arial'\";
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('WAF Challenge', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('WAF Challenge', 4, 17);
            const dataURL = canvas.toDataURL();
            signals.canvasHash = await hashString(dataURL);
        }} catch (e) {{
            signals.canvasHash = 'error';
        }}

        // WebGL fingerprint
        try {{
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            if (gl) {{
                const ext = gl.getExtension('WEBGL_debug_renderer_info');
                if (ext) {{
                    signals.webglVendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
                    signals.webglRenderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
                }}
            }}
        }} catch (e) {{
            signals.webglVendor = 'error';
            signals.webglRenderer = 'error';
        }}

        // Navigator properties
        signals.hardwareConcurrency = navigator.hardwareConcurrency || 0;
        signals.deviceMemory = navigator.deviceMemory || 0;

        // Screen properties
        signals.screenWidth = screen.width;
        signals.screenHeight = screen.height;
        signals.colorDepth = screen.colorDepth;

        // Timing variance
        const timings = [];
        for (let i = 0; i < 10; i++) {{
            const start = performance.now();
            let x = 0;
            for (let j = 0; j < 1000; j++) x += Math.sqrt(j);
            timings.push(performance.now() - start);
        }}
        const mean = timings.reduce((a, b) => a + b) / timings.length;
        const variance = timings.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / timings.length;
        signals.timingVariance = variance;

        return signals;
    }}

    async function computeProofOfWork(challengeId, difficulty) {{
        const target = '0'.repeat(Math.ceil(difficulty / 4));
        let nonce = 0;
        const start = Date.now();

        while (true) {{
            const data = challengeId + ':' + nonce + ':' + start;
            const hash = await hashString(data);

            if (hash.startsWith(target)) {{
                return nonce;
            }}

            nonce++;

            // Yield to prevent UI freeze
            if (nonce % 100000 === 0) {{
                await new Promise(r => setTimeout(r, 0));
            }}
        }}
    }}

    async function hashString(str) {{
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }}
    </script>
</body>
</html>"#)
    }

    /// Validate a challenge response
    pub async fn validate_response(
        &self,
        client_ip: &str,
        signals: FingerprintSignals,
        pow_nonce: u64,
        challenge_id: &str,
    ) -> std::result::Result<bool, waf_common::WafError> {
        // Find the challenge for this client
        let mut challenges = self.challenges.write().await;
        
        let token = challenges
            .get_mut(client_ip)
            .ok_or(WafError::ChallengeFailed("No challenge found".to_string()))?;

        // Check challenge hasn't expired
        if token.is_expired() {
            return Ok(false);
        }

        // Validate proof-of-work
        let pow_valid = self.verify_pow(challenge_id, pow_nonce);
        let mut signals = signals;
        signals.pow_valid = pow_valid;

        // Calculate fingerprint score
        let fingerprint_score = signals.calculate_score();

        // Update token
        token.fingerprint_score = fingerprint_score;

        if pow_valid {
            token.mark_solved();
            // Extend token validity
            token.expires_at = Utc::now() + chrono::Duration::seconds(self.token_timeout_secs as i64);
            return Ok(true);
        }

        Ok(false)
    }

    /// Verify proof-of-work solution
    fn verify_pow(&self, challenge_id: &str, nonce: u64) -> bool {
        // Simple verification - check hash has required leading zeros
        let data = format!("{}:{}", challenge_id, nonce);
        let hash = Sha256::digest(data.as_bytes());
        let hash_str = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        
        let required_zeros = (self.pow_difficulty + 3) / 4; // Convert bits to hex chars
        let end_idx = (required_zeros as usize).min(hash_str.len());
        hash_str[..end_idx].chars()
            .all(|c| c == '0')
    }

    /// Check if a client has a valid token
    pub async fn has_valid_token(&self, client_ip: &str) -> bool {
        if let Some(token) = self.challenges.read().await.get(client_ip) {
            token.is_valid()
        } else {
            false
        }
    }

    /// Remove expired challenges
    pub async fn cleanup_expired(&self) -> usize {
        let mut challenges = self.challenges.write().await;
        let before = challenges.len();
        challenges.retain(|_, token| !token.is_expired());
        before - challenges.len()
    }
}

impl Default for ChallengeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_generation() {
        let generator = ChallengeGenerator::new();
        let challenge_id = generator.generate_challenge("192.168.1.1").await;
        assert!(!challenge_id.is_empty());
    }

    #[tokio::test]
    async fn test_challenge_page_generation() {
        let generator = ChallengeGenerator::new();
        let page = generator.generate_challenge_page("test-challenge-id");
        assert!(page.contains("Security Verification"));
        assert!(page.contains("canvas"));
        assert!(page.contains("WebGL"));
    }

    #[test]
    fn test_fingerprint_score_calculation() {
        let signals = FingerprintSignals {
            canvas_hash: Some("abc123".to_string()),
            webgl_vendor: Some("Intel Inc.".to_string()),
            webgl_renderer: Some("Intel Iris".to_string()),
            hardware_concurrency: Some(8),
            device_memory: Some(8.0),
            screen_width: Some(1920),
            screen_height: Some(1080),
            color_depth: Some(24),
            timing_variance: Some(50.0),
            pow_nonce: Some(12345),
            pow_valid: true,
        };

        let score = signals.calculate_score();
        assert!(score >= 50); // Should be high with good signals
    }

    #[test]
    fn test_headless_detection() {
        let signals = FingerprintSignals {
            webgl_renderer: Some("SwiftShader".to_string()),
            timing_variance: Some(0.01),
            ..Default::default()
        };

        assert!(signals.is_headless());
    }

    #[tokio::test]
    async fn test_token_validation() {
        let generator = ChallengeGenerator::new();
        let client_ip = "192.168.1.100";
        
        // Generate challenge
        let challenge_id = generator.generate_challenge(client_ip).await;
        
        // Verify proof-of-work (we need to compute correct nonce)
        let valid = generator.verify_pow(&challenge_id, 0);
        // First nonce won't be valid, but this tests the function
        assert!(!valid); // Should be false for nonce 0
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let generator = ChallengeGenerator::new();
        generator.generate_challenge("192.168.1.1").await;
        
        // Cleanup should remove expired challenges (none should be expired yet)
        let cleaned = generator.cleanup_expired().await;
        assert_eq!(cleaned, 0);
    }
}