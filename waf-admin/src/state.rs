//! Admin state management
//!
//! Manages WAF admin service state including rules and statistics.
//!
//! ## State Management
//!
//! The admin service maintains:
//! - Rule registry (loaded rules and their status)
//! - Statistics (request counts, attack counts)
//! - Configuration (runtime configuration)
//!
//! All state is stored in-memory for the admin service.
//! Rules are synchronized with the WAF core via hot reload.

use std::sync::{Arc, RwLock};
use waf_common::Rule;

/// Admin service state
pub struct AdminState {
    /// Loaded rules registry
    pub rules: RwLock<Vec<Rule>>,
    /// Statistics data
    pub stats: Arc<RwLock<crate::Stats>>,
}

impl AdminState {
    /// Create new admin state
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            stats: Arc::new(RwLock::new(crate::Stats::default())),
        }
    }
}

impl Default for AdminState {
    fn default() -> Self {
        Self::new()
    }
}
