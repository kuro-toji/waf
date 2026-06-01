//! WAF Bot Detector
//!
//! Bot detection through fingerprinting, behavioral analysis, and challenges.
//!
//! ## Components
//!
//! 1. **Fingerprint Collector**: Gathers browser/client fingerprints
//! 2. **Reputation Database**: Maintains IP reputation scores
//! 3. **Challenge Generator**: Creates JS/CAPTCHA challenges
//! 4. **Bot Detector**: Unified detection interface
//! 5. **TLS Fingerprinting**: JA3/JA4 client identification
//!
//! ## Integration
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

pub mod challenge;
pub mod detector;
pub mod fingerprint;
pub mod reputation;
pub mod tls_fingerprint;

pub use challenge::*;
pub use detector::*;
pub use fingerprint::*;
pub use reputation::*;
pub use tls_fingerprint::*;
