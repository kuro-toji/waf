//! Bot Challenge System
//!
//! Generates and validates challenges for suspected bots.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

/// Challenge types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeType {
    Javascript,
    Captcha,
    RateLimit,
}

/// Challenge response
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge_type: ChallengeType,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_ip: String,
    pub solved: bool,
}

impl ChallengeResponse {
    /// Check if challenge is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Challenge generator
pub struct ChallengeGenerator {
    active_challenges: RwLock<HashMap<String, ChallengeResponse>>,
    challenge_timeout_seconds: i64,
}

impl ChallengeGenerator {
    /// Create a new challenge generator
    pub fn new(timeout_seconds: u64) -> Self {
        Self {
            active_challenges: RwLock::new(HashMap::new()),
            challenge_timeout_seconds: timeout_seconds as i64,
        }
    }

    /// Generate a JavaScript challenge
    pub fn generate_js_challenge(&self, client_ip: &str) -> String {
        let challenge_id = Uuid::new_v4().to_string();

        // Store challenge
        let response = ChallengeResponse {
            challenge_id: challenge_id.clone(),
            challenge_type: ChallengeType::Javascript,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(self.challenge_timeout_seconds),
            client_ip: client_ip.to_string(),
            solved: false,
        };

        self.active_challenges
            .write()
            .unwrap()
            .insert(challenge_id.clone(), response);

        // Generate JavaScript challenge HTML
        self.generate_js_html(&challenge_id)
    }

    /// Generate CAPTCHA challenge
    pub fn generate_captcha_challenge(&self, client_ip: &str) -> String {
        let challenge_id = Uuid::new_v4().to_string();

        let response = ChallengeResponse {
            challenge_id: challenge_id.clone(),
            challenge_type: ChallengeType::Captcha,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(self.challenge_timeout_seconds),
            client_ip: client_ip.to_string(),
            solved: false,
        };

        self.active_challenges
            .write()
            .unwrap()
            .insert(challenge_id.clone(), response);

        self.generate_captcha_html(&challenge_id)
    }

    /// Validate challenge response
    pub fn validate_response(&self, challenge_id: &str, solution: &str) -> Result<bool, String> {
        let mut challenges = self.active_challenges.write().unwrap();

        if let Some(challenge) = challenges.get_mut(challenge_id) {
            if challenge.is_expired() {
                return Err("Challenge expired".to_string());
            }

            let valid = match challenge.challenge_type {
                ChallengeType::Javascript => {
                    // For JS challenge, verify the solution hash matches
                    let expected = self.hash_solution(challenge_id);
                    solution == expected
                }
                ChallengeType::Captcha => {
                    // For CAPTCHA, verify against stored answer
                    solution == "captcha_solution" // Simplified
                }
                ChallengeType::RateLimit => {
                    // Rate limit challenges just need acknowledgment
                    true
                }
            };

            if valid {
                challenge.solved = true;
            }

            Ok(valid)
        } else {
            Err("Challenge not found".to_string())
        }
    }

    /// Check if client passed challenge
    pub fn is_challenge_passed(&self, client_ip: &str) -> bool {
        let challenges = self.active_challenges.read().unwrap();
        challenges
            .values()
            .any(|c| c.client_ip == client_ip && c.solved && !c.is_expired())
    }

    /// Get active challenge for client
    pub fn get_active_challenge(&self, client_ip: &str) -> Option<&ChallengeResponse> {
        let challenges = self.active_challenges.read().unwrap();
        challenges
            .values()
            .find(|c| c.client_ip == client_ip && !c.solved && !c.is_expired())
    }

    /// Cleanup expired challenges
    pub fn cleanup_expired(&self) {
        let mut challenges = self.active_challenges.write().unwrap();
        challenges.retain(|_, c| !c.is_expired());
    }

    /// Hash solution for verification
    fn hash_solution(&self, challenge_id: &str) -> String {
        format!("{:x}", challenge_id.len() * 12345)
    }

    /// Generate JavaScript challenge HTML
    fn generate_js_html(&self, challenge_id: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Verification Required</title>
</head>
<body>
    <script>
        // Solve challenge by computing proof-of-work
        var challenge_id = "{challenge_id}";
        var timestamp = Date.now();
        var proof = 0;
        
        // Simple proof-of-work: find number where hash ends in "cafe"
        // In production, use a stronger puzzle
        function solve() {{
            for (var i = 0; i < 100000; i++) {{
                var test = challenge_id + i.toString();
                var hash = 0;
                for (var j = 0; j < test.length; j++) {{
                    hash = (hash * 31 + test.charCodeAt(j)) & 0xffffffff;
                }}
                if ((hash & 0xffff) === 0xcafe) {{
                    proof = i;
                    break;
                }}
            }}
            return proof;
        }}
        
        var solution = solve();
        
        // Send solution
        fetch('/_waf_challenge?solve=' + challenge_id + '&proof=' + solution)
            .then(function(response) {{
                if (response.ok) {{
                    location.reload();
                }}
            }});
    </script>
    <noscript>
        <p>Please enable JavaScript to continue.</p>
    </noscript>
</body>
</html>"#,
            challenge_id = challenge_id
        )
    }

    /// Generate CAPTCHA HTML
    fn generate_captcha_html(&self, challenge_id: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>CAPTCHA Verification</title>
</head>
<body>
    <h1>Please complete the verification</h1>
    <form method="POST" action="/_waf_challenge">
        <input type="hidden" name="challenge_id" value="{challenge_id}">
        <p>What is 2 + 2?</p>
        <input type="text" name="answer" required>
        <button type="submit">Submit</button>
    </form>
</body>
</html>"#,
            challenge_id = challenge_id
        )
    }
}

impl Default for ChallengeGenerator {
    fn default() -> Self {
        Self::new(300)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_js_challenge_generation() {
        let generator = ChallengeGenerator::new(300);
        let html = generator.generate_js_challenge("192.168.1.1");
        assert!(html.contains("challenge_id"));
        assert!(html.contains("Verification Required"));
    }

    #[test]
    fn test_challenge_expiration() {
        let response = ChallengeResponse {
            challenge_id: "test".to_string(),
            challenge_type: ChallengeType::Javascript,
            created_at: Utc::now() - Duration::seconds(400),
            expires_at: Utc::now() - Duration::seconds(100),
            client_ip: "192.168.1.1".to_string(),
            solved: false,
        };
        assert!(response.is_expired());
    }
}
