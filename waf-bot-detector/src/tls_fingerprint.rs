//! TLS Fingerprint Extraction (JA3/JA4)
//!
//! Implements TLS client fingerprinting for bot detection. JA3/JA4 are
//! techniques that create a hash from TLS ClientHello parameters to
//! identify clients based on their TLS implementation differences.
//!
//! ## JA3 Format
//!
//! `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
//! Example: `771,4865-4866-4867,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0`
//!
//! ## JA4 Format (Newer)
//!
//! `t13d1516h2_8daaf6152771_02713d6af862`
//!
//! ## Usage
//!
//! ```rust
//! use waf_bot_detector::tls_fingerprint::{Ja3Hasher, TlsFingerprintMatcher};
//!
//! let hasher = Ja3Hasher::new();
//! let client_hello_bytes = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00];
//! let ja3_hash = hasher.compute_ja3_from_bytes(&client_hello_bytes);
//!
//! let matcher = TlsFingerprintMatcher::new();
//! if let Some(hash) = ja3_hash {
//!     let bot_score = matcher.calculate_bot_score(&hash);
//! }
//! ```

use std::collections::HashMap;
use std::fmt;

/// JA3 TLS fingerprint data extracted from ClientHello
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3Data {
    /// TLS version (e.g., 0x303 for TLS 1.2, 0x304 for TLS 1.3)
    pub version: u16,
    /// List of cipher suites (IANA assigned numbers)
    pub cipher_suites: Vec<u16>,
    /// List of extension types
    pub extensions: Vec<u16>,
    /// Elliptic curves (extension 10)
    pub elliptic_curves: Vec<u16>,
    /// Elliptic curve point formats (extension 11)
    pub ec_point_formats: Vec<u8>,
}

impl Ja3Data {
    /// Create empty JA3 data
    pub fn new() -> Self {
        Self {
            version: 0,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            elliptic_curves: Vec::new(),
            ec_point_formats: Vec::new(),
        }
    }

    /// Get the JA3 string representation
    pub fn to_ja3_string(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.version,
            Self::join_u16(&self.cipher_suites),
            Self::join_u16(&self.extensions),
            Self::join_u16(&self.elliptic_curves),
            Self::join_u8(&self.ec_point_formats),
        )
    }

    fn join_u16(values: &[u16]) -> String {
        values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    }

    fn join_u8(values: &[u8]) -> String {
        values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl Default for Ja3Data {
    fn default() -> Self {
        Self::new()
    }
}

/// JA3 hash (MD5 of JA3 string)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja3Hash(pub String);

impl Ja3Hash {
    /// Create from string hash
    pub fn new(hash: String) -> Self {
        Self(hash)
    }

    /// Get the hash string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Ja3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// JA4 TLS fingerprint (newer, more detailed format)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja4Data {
    /// Transport protocol version (t13 = TLS 1.3, t12 = TLS 1.2)
    pub proto: String,
    /// Number of cipher suites (2 digits)
    pub cipher_count: String,
    /// First cipher suite in hex (4 digits)
    pub first_cipher: String,
    /// Number of extensions (2 digits)
    pub extension_count: String,
    /// SNI hash (first 12 chars of SHA256)
    pub sni_hash: String,
    /// ALPN first value hash (first 12 chars)
    pub alpn_hash: String,
}

impl Ja4Data {
    /// Create empty JA4 data
    pub fn new() -> Self {
        Self {
            proto: "00".to_string(),
            cipher_count: "00".to_string(),
            first_cipher: "0000".to_string(),
            extension_count: "00".to_string(),
            sni_hash: "000000000000".to_string(),
            alpn_hash: "000000000000".to_string(),
        }
    }

    /// Get the JA4 string representation
    pub fn to_ja4_string(&self) -> String {
        format!(
            "t{}d{}{}_{}_{}",
            self.proto, self.cipher_count, self.first_cipher, self.extension_count, self.sni_hash
        )
    }
}

impl Default for Ja4Data {
    fn default() -> Self {
        Self::new()
    }
}

/// GREASE values in TLS (reserved values that should be ignored)
const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Check if a value is a GREASE value
fn is_grease(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

/// JA3 hash computation
pub struct Ja3Hasher;

impl Ja3Hasher {
    /// Create new JA3 hasher
    pub fn new() -> Self {
        Self
    }

    /// Compute JA3 hash from raw TLS ClientHello bytes
    /// Returns None if parsing fails
    pub fn compute_ja3_from_bytes(&self, data: &[u8]) -> Option<Ja3Hash> {
        let ja3_string = self.parse_client_hello(data)?;
        let digest = md5::compute(ja3_string.as_bytes());
        let hash = format!("{:x}", digest);
        Some(Ja3Hash(hash))
    }

    /// Parse ClientHello and produce JA3 string
    fn parse_client_hello(&self, data: &[u8]) -> Option<String> {
        // TLS Record structure:
        // - ContentType (1 byte) = 0x16 for Handshake
        // - ProtocolVersion (2 bytes)
        // - Length (2 bytes)
        // - Handshake Type (1 byte) = 0x01 for ClientHello
        // - Handshake length (3 bytes)
        // - ClientHello content...

        if data.len() < 5 {
            return None;
        }

        // Skip to handshake (after record header)
        let handshake = &data[5..];
        if handshake.len() < 4 {
            return None;
        }

        // Get ClientHello length (first 3 bytes after type)
        let hello_len = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | (handshake[3] as usize);

        if handshake.len() < 4 + hello_len {
            return None;
        }

        // Parse ClientHello body
        let client_version = ((handshake[4] as u16) << 8) | (handshake[5] as u16);

        // Skip client random (32 bytes)
        let mut pos = 4 + 32;

        // Session ID length
        if pos >= handshake.len() {
            return None;
        }
        let session_id_len = handshake[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites length
        if pos + 2 > handshake.len() {
            return None;
        }
        let cipher_suites_len = ((handshake[pos] as usize) << 8) | (handshake[pos + 1] as usize);
        pos += 2;

        // Parse cipher suites
        let mut ciphers = Vec::new();
        let cipher_end = pos + cipher_suites_len;
        while pos + 2 <= cipher_end && pos + 2 <= handshake.len() {
            let cipher = ((handshake[pos] as u16) << 8) | (handshake[pos + 1] as u16);
            if !is_grease(cipher) {
                ciphers.push(cipher);
            }
            pos += 2;
        }

        // Compression methods
        if pos >= handshake.len() {
            return None;
        }
        let compression_len = handshake[pos] as usize;
        pos += 1 + compression_len;

        // Extensions
        let mut extensions = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();

        if pos + 2 > handshake.len() {
            return None;
        }
        let extensions_len = ((handshake[pos] as usize) << 8) | (handshake[pos + 1] as usize);
        pos += 2;

        let extensions_end = pos + extensions_len;
        while pos + 4 <= extensions_end && pos + 4 <= handshake.len() {
            let ext_type = ((handshake[pos] as u16) << 8) | (handshake[pos + 1] as u16);
            let ext_len = ((handshake[pos + 2] as usize) << 8) | (handshake[pos + 3] as usize);
            pos += 4;

            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }

            // Parse extension data based on type
            match ext_type {
                0x0A
                    // Elliptic curves (extension 10)
                    if pos + 2 <= extensions_end && pos + 2 + ext_len <= handshake.len() => {
                        let curves_len =
                            ((handshake[pos] as usize) << 8) | (handshake[pos + 1] as usize);
                        let curves_start = pos + 2;
                        for i in (0..curves_len).step_by(2) {
                            if curves_start + i + 2 <= extensions_end
                                && curves_start + i + ext_len <= handshake.len()
                            {
                                let curve = ((handshake[curves_start + i] as u16) << 8)
                                    | (handshake[curves_start + i + 1] as u16);
                                if !is_grease(curve) {
                                    elliptic_curves.push(curve);
                                }
                            }
                        }
                    }
                0x0B
                    // EC point formats (extension 11)
                    if pos < extensions_end && pos + 1 + ext_len <= handshake.len() => {
                        let formats_len = handshake[pos] as usize;
                        for i in 0..formats_len {
                            if pos + 1 + i < extensions_end && pos + 1 + ext_len <= handshake.len()
                            {
                                ec_point_formats.push(handshake[pos + 1 + i]);
                            }
                        }
                    }
                _ => {}
            }

            pos += ext_len;
        }

        Some(format!(
            "{},{},{},{},{}",
            client_version,
            ciphers
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            extensions
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            elliptic_curves
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            ec_point_formats
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        ))
    }

    /// Create JA3 data from raw bytes
    pub fn extract_ja3_data(&self, data: &[u8]) -> Option<Ja3Data> {
        // Simplified extraction for testing
        if data.len() < 5 {
            return None;
        }

        let mut ja3 = Ja3Data::new();

        // Get version from record
        ja3.version = ((data[1] as u16) << 8) | (data[2] as u16);

        // Rest is handshake data - simplified parsing
        let handshake = &data[5..];
        if handshake.len() < 4 {
            return None;
        }

        // Set some defaults for testing
        ja3.cipher_suites = vec![0x1301, 0x1302, 0x1303]; // TLS 1.3 cipher suites
        ja3.extensions = vec![0x002B, 0x0033, 0x001D]; // Known extensions
        ja3.elliptic_curves = vec![0x0017, 0x0018, 0x0019]; // Prime curves

        Some(ja3)
    }
}

impl Default for Ja3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Bot category based on TLS fingerprint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotCategory {
    /// Known good browser
    LegitimateBrowser,
    /// Vulnerability scanner
    VulnerabilityScanner,
    /// Selenium/Playwright headless browser
    HeadlessBrowser,
    /// Custom bot or scraper
    CustomBot,
    /// VPN/Proxy exit node
    VpnProxy,
    /// Unknown fingerprint
    Unknown,
}

/// Bot signature from fingerprint database
#[derive(Debug, Clone)]
pub struct BotSignature {
    pub category: BotCategory,
    pub confidence: u8,
    pub description: &'static str,
}

/// TLS fingerprint matcher for bot detection
pub struct TlsFingerprintMatcher {
    /// Known bot fingerprints
    known_bots: HashMap<Ja3Hash, BotSignature>,
    /// Known browser fingerprints
    known_browsers: HashMap<Ja3Hash, &'static str>,
}

impl TlsFingerprintMatcher {
    /// Create new matcher with default signatures
    pub fn new() -> Self {
        let mut matcher = Self {
            known_bots: HashMap::new(),
            known_browsers: HashMap::new(),
        };
        matcher.load_default_signatures();
        matcher
    }

    /// Load default known bot and browser signatures
    fn load_default_signatures(&mut self) {
        // Common headless browser JA3 hashes (example hashes)
        // These would be populated from real fingerprint databases

        // Note: These are example placeholder hashes
        // In production, use a real fingerprint database

        // Known bots
        self.known_bots.insert(
            Ja3Hash::new("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string()),
            BotSignature {
                category: BotCategory::VulnerabilityScanner,
                confidence: 90,
                description: "Common vulnerability scanner",
            },
        );

        // Known browsers (partial hash as example)
        self.known_browsers
            .insert(Ja3Hash::new("firefox_ja3_hash_here".to_string()), "Firefox");
    }

    /// Check if a JA3 hash matches a known bot
    pub fn is_known_bot(&self, ja3: &Ja3Hash) -> Option<&BotSignature> {
        self.known_bots.get(ja3)
    }

    /// Check if a JA3 hash matches a known browser
    pub fn is_known_browser(&self, ja3: &Ja3Hash) -> Option<&'static str> {
        self.known_browsers.get(ja3).copied()
    }

    /// Calculate bot score from JA3 hash (0-100)
    /// - 0-30: Likely legitimate browser
    /// - 31-60: Unknown/suspicious
    /// - 61-100: Likely bot
    pub fn calculate_bot_score(&self, ja3: &Ja3Hash) -> u8 {
        // Check known bot first
        if let Some(sig) = self.is_known_bot(ja3) {
            return sig.confidence;
        }

        // Check known browser
        if self.is_known_browser(ja3).is_some() {
            return 5; // Very low score for known browser
        }

        // Unknown fingerprint
        30
    }

    /// Get bot category from fingerprint
    pub fn get_category(&self, ja3: &Ja3Hash) -> BotCategory {
        self.is_known_bot(ja3)
            .map(|sig| sig.category)
            .unwrap_or(BotCategory::Unknown)
    }

    /// Add a known bot signature
    pub fn add_bot_signature(&mut self, ja3: Ja3Hash, signature: BotSignature) {
        self.known_bots.insert(ja3, signature);
    }

    /// Add a known browser signature
    pub fn add_browser_signature(&mut self, ja3: Ja3Hash, browser_name: &'static str) {
        self.known_browsers.insert(ja3, browser_name);
    }

    /// Get count of known bot signatures
    pub fn bot_signature_count(&self) -> usize {
        self.known_bots.len()
    }

    /// Get count of known browser signatures
    pub fn browser_signature_count(&self) -> usize {
        self.known_browsers.len()
    }
}

impl Default for TlsFingerprintMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja3_data_creation() {
        let mut data = Ja3Data::new();
        data.version = 0x0303; // TLS 1.2
        data.cipher_suites = vec![0x002F, 0x009C, 0xC02C];
        data.extensions = vec![0x002B, 0x0033, 0x0010];

        let ja3_string = data.to_ja3_string();
        assert!(ja3_string.contains("771")); // TLS 1.2
    }

    #[test]
    fn test_ja4_data_creation() {
        let mut data = Ja4Data::new();
        data.proto = "13".to_string();
        data.cipher_count = "03".to_string();
        data.first_cipher = "1301".to_string();

        let ja4_string = data.to_ja4_string();
        assert!(ja4_string.starts_with("t13"));
    }

    #[test]
    fn test_grease_filtering() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0xFAFA));
        assert!(!is_grease(0x002F));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn test_bot_score_calculation() {
        let matcher = TlsFingerprintMatcher::new();

        // Unknown hash should get moderate score
        let unknown = Ja3Hash::new("unknown_hash_123456".to_string());
        let score = matcher.calculate_bot_score(&unknown);
        assert!(score <= 30); // Unknown should be 30

        // Known bot hash (if we had one) should get higher score
    }

    #[test]
    fn test_ja3_hasher_minimal_data() {
        let hasher = Ja3Hasher::new();

        // Too short data should return None
        let result = hasher.compute_ja3_from_bytes(&[0x16, 0x03, 0x03]);
        assert!(result.is_none());
    }
}
