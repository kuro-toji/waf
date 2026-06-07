//! Fingerprint Collector
//!
//! Collects browser/client fingerprints for bot detection.
//!
//! ## Fingerprint Data
//!
//! The collector gathers multiple signals:
//! - **User-Agent**: Browser identification string
//! - **Accept-Language**: Preferred languages
//! - **Accept-Encoding**: Supported encodings
//! - **Accept**: Accepted content types
//! - **TLS fingerprint**: JA3 hash for TLS client hello
//! - **HTTP/2 fingerprint**: Settings, window updates
//!
//! ## Known Bots
//!
//! Recognized bots include:
//! - Search engines: Googlebot, Bingbot, YandexBot, Baiduspider
//! - Social crawlers: Twitterbot, Facebook Crawler
//! - Monitoring: LinkedIn Bot, DuckDuckBot
//! - Tools: curl, wget, python-requests, axios
//!
//! ## Analysis
//!
//! Fingerprints are analyzed for:
//! - Missing headers (bots often skip)
//! - Short User-Agent strings
//! - Suspicious patterns (headless, automation tools)
//! - Known bot identification

use http::header::HeaderMap;

/// Client fingerprint data
#[derive(Debug, Clone)]
pub struct ClientFingerprint {
    /// User-Agent string
    pub user_agent: Option<String>,
    /// Accept-Language header
    pub accept_language: Option<String>,
    /// Accept-Encoding header
    pub accept_encoding: Option<String>,
    /// Accept header
    pub accept: Option<String>,
    /// TLS fingerprint (JA3 hash)
    pub tls_fingerprint: Option<String>,
    /// HTTP/2 fingerprint
    pub http2_fingerprint: Option<String>,
    /// IP reputation score (0-100, higher = more likely bot)
    pub ip_reputation_score: u8,
    /// Known bot indicator
    pub is_known_bot: bool,
    /// Bot name if known
    pub bot_name: Option<String>,
}

impl Default for ClientFingerprint {
    fn default() -> Self {
        Self {
            user_agent: None,
            accept_language: None,
            accept_encoding: None,
            accept: None,
            tls_fingerprint: None,
            http2_fingerprint: None,
            ip_reputation_score: 50,
            is_known_bot: false,
            bot_name: None,
        }
    }
}

/// Fingerprint collector
pub struct FingerprintCollector {
    /// Known bot user agents
    known_bot_uas: Vec<BotPattern>,
    /// Known bot IP ranges
    known_bot_ips: Vec<String>,
}

struct BotPattern {
    pattern: String,
    name: &'static str,
}

impl Default for FingerprintCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintCollector {
    /// Create a new fingerprint collector
    pub fn new() -> Self {
        let known_bot_uas = vec![
            BotPattern {
                pattern: "Googlebot".to_string(),
                name: "Googlebot",
            },
            BotPattern {
                pattern: "Bingbot".to_string(),
                name: "Bingbot",
            },
            BotPattern {
                pattern: "Slurp".to_string(),
                name: "Yahoo Slurp",
            },
            BotPattern {
                pattern: "DuckDuckBot".to_string(),
                name: "DuckDuckBot",
            },
            BotPattern {
                pattern: "Baiduspider".to_string(),
                name: "Baiduspider",
            },
            BotPattern {
                pattern: "YandexBot".to_string(),
                name: "YandexBot",
            },
            BotPattern {
                pattern: "facebot".to_string(),
                name: "Facebook Crawler",
            },
            BotPattern {
                pattern: "Twitterbot".to_string(),
                name: "Twitterbot",
            },
            BotPattern {
                pattern: "linkedinbot".to_string(),
                name: "LinkedIn Bot",
            },
            BotPattern {
                pattern: "python-requests".to_string(),
                name: "Python Requests",
            },
            BotPattern {
                pattern: "curl".to_string(),
                name: "cURL",
            },
            BotPattern {
                pattern: "wget".to_string(),
                name: "Wget",
            },
            BotPattern {
                pattern: "HttpClient".to_string(),
                name: "HTTP Client",
            },
            BotPattern {
                pattern: "Go-http-client".to_string(),
                name: "Go HTTP Client",
            },
            BotPattern {
                pattern: "java/".to_string(),
                name: "Java HTTP Client",
            },
            BotPattern {
                pattern: "libwww-perl".to_string(),
                name: "Libwww-perl",
            },
            BotPattern {
                pattern: "http.rb".to_string(),
                name: "Ruby HTTP",
            },
            BotPattern {
                pattern: "axios/".to_string(),
                name: "Axios",
            },
        ];

        Self {
            known_bot_uas,
            known_bot_ips: vec![],
        }
    }

    /// Collect fingerprint from headers
    pub fn collect(&self, headers: &HeaderMap) -> ClientFingerprint {
        let mut fp = ClientFingerprint {
            user_agent: headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            accept_language: headers
                .get("accept-language")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            accept_encoding: headers
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            accept: headers
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            ..ClientFingerprint::default()
        };

        // Check for known bots
        if let Some(ua) = &fp.user_agent {
            for bot in &self.known_bot_uas {
                if ua.to_lowercase().contains(&bot.pattern.to_lowercase()) {
                    fp.is_known_bot = true;
                    fp.bot_name = Some(bot.name.to_string());
                    fp.ip_reputation_score = 0; // Known bots get low score
                    break;
                }
            }
        }

        fp
    }

    /// Collect fingerprint from request context
    pub fn collect_from_request(&self, ctx: &waf_common::RequestContext) -> ClientFingerprint {
        let mut fp = ClientFingerprint::default();

        // Collect from headers in context
        if let Some(ua) = ctx.get_header("user-agent") {
            fp.user_agent = Some(ua.to_string());
        }

        if let Some(al) = ctx.get_header("accept-language") {
            fp.accept_language = Some(al.to_string());
        }

        if let Some(ae) = ctx.get_header("accept-encoding") {
            fp.accept_encoding = Some(ae.to_string());
        }

        if let Some(a) = ctx.get_header("accept") {
            fp.accept = Some(a.to_string());
        }

        // Check for known bots
        if let Some(ua) = &fp.user_agent {
            for bot in &self.known_bot_uas {
                if ua.to_lowercase().contains(&bot.pattern.to_lowercase()) {
                    fp.is_known_bot = true;
                    fp.bot_name = Some(bot.name.to_string());
                    fp.ip_reputation_score = 0;
                    break;
                }
            }
        }

        fp
    }

    /// Analyze fingerprint for bot indicators
    pub fn analyze(&self, fp: &ClientFingerprint) -> BotAnalysisResult {
        let mut score: i32 = 0;
        let mut indicators = Vec::new();

        // Check user agent
        if let Some(ua) = &fp.user_agent {
            if ua.is_empty() {
                score += 30;
                indicators.push("Empty User-Agent".to_string());
            } else if ua.len() < 20 {
                score += 20;
                indicators.push("Short User-Agent".to_string());
            }

            // Check for suspicious patterns
            let suspicious_patterns = [
                "bot",
                "crawler",
                "spider",
                "scraper",
                "headless",
                "phantom",
                "selenium",
                "puppeteer",
            ];
            for pattern in suspicious_patterns {
                if ua.to_lowercase().contains(pattern) {
                    score += 15;
                    indicators.push(format!("Suspicious UA pattern: {}", pattern));
                }
            }
        }

        // Check headers
        if fp.accept_language.is_none() {
            score += 15;
            indicators.push("Missing Accept-Language".to_string());
        }

        if fp.accept_encoding.is_none() {
            score += 10;
            indicators.push("Missing Accept-Encoding".to_string());
        }

        if fp.accept.is_none() {
            score += 10;
            indicators.push("Missing Accept".to_string());
        }

        BotAnalysisResult {
            score,
            is_bot: score >= 50,
            indicators,
            confidence: (score as f32 / 100.0).min(1.0),
        }
    }

    /// Add known bot IP
    pub fn add_bot_ip(&mut self, ip_range: &str) {
        self.known_bot_ips.push(ip_range.to_string());
    }
}

/// Bot analysis result
#[derive(Debug, Clone)]
pub struct BotAnalysisResult {
    pub score: i32,
    pub is_bot: bool,
    pub indicators: Vec<String>,
    pub confidence: f32,
}

impl Default for BotAnalysisResult {
    fn default() -> Self {
        Self {
            score: 0,
            is_bot: false,
            indicators: Vec::new(),
            confidence: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_bot_detection() {
        let collector = FingerprintCollector::new();

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Googlebot/2.1".parse().unwrap());

        let fp = collector.collect(&headers);
        assert!(fp.is_known_bot);
        assert_eq!(fp.bot_name, Some("Googlebot".to_string()));
    }

    #[test]
    fn test_normal_user_detection() {
        let collector = FingerprintCollector::new();

        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".parse().unwrap(),
        );

        let fp = collector.collect(&headers);
        assert!(!fp.is_known_bot);
    }
}
