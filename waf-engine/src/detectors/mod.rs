//! Attack Detectors
//!
//! Individual attack detection modules for OWASP Top 10 and more.
//!
//! ## Available Detectors
//!
//! Each detector specializes in a specific attack type:
//!
//! | Detector | Attack Type | Confidence Range |
//! |----------|-------------|------------------|
//! | [`sqli`](sqli::SqlInjectionDetector) | SQL Injection | 0.6 - 0.95 |
//! | [`xss`](xss::XssDetector) | Cross-Site Scripting | 0.7 - 0.95 |
//! | [`csrf`](csrf::CsrfDetector) | CSRF | 0.6 - 0.9 |
//! | [`path_traversal`](path_traversal::PathTraversalDetector) | Path Traversal | 0.7 - 0.95 |
//! | [`command_injection`](command_injection::CommandInjectionDetector) | Command Injection | 0.6 - 0.95 |
//! | [`xxe`](xxe::XxeDetector) | XML External Entity | 0.7 - 0.95 |
//! | [`ldap_injection`](ldap_injection::LdapInjectionDetector) | LDAP Injection | 0.7 - 0.85 |
//! | [`lfi`](lfi::LfiDetector) | Local File Inclusion | 0.8 - 0.95 |
//! | [`rfi`](rfi::RfiDetector) | Remote File Inclusion | 0.8 - 0.95 |
//!
//! ## Usage
//!
//! ```rust
//! use waf_engine::detectors::{SqlInjectionDetector, XssDetector};
//!
//! let sqli = SqlInjectionDetector::new();
//! let result = sqli.detect("1 UNION SELECT * FROM users");
//! if result.detected {
//!     println!("SQL injection: {}", result.pattern);
//! }
//! ```

pub mod command_injection;
pub mod csrf;
pub mod ldap_injection;
pub mod lfi;
pub mod path_traversal;
pub mod rfi;
pub mod sqli;
pub mod xss;
pub mod xxe;

pub use command_injection::*;
pub use csrf::*;
pub use ldap_injection::*;
pub use lfi::*;
pub use path_traversal::*;
pub use rfi::*;
pub use sqli::*;
pub use xss::*;
pub use xxe::*;
