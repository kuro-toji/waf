//! Admin state management

use std::sync::{Arc, RwLock};
use waf_common::Rule;

pub struct AdminState {
    pub rules: RwLock<Vec<Rule>>,
    // Add more state as needed
}
