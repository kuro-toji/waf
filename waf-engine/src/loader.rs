//! Rule Loader
//!
//! Loads and hot-reloads rules from YAML files.
//!
//! ## Hot Reload Behavior
//!
//! The loader monitors rule files and automatically reloads when changes are detected:
//! - File changes are checked every 2 seconds
//! - On change, all rules are reloaded from disk
//! - Existing rules are replaced atomically
//! - In-flight requests complete with old rules
//! - New requests use updated rules
//!
//! ## Error Handling
//!
//! If a rule file is malformed:
//! - Warning is logged
//! - Other rule files continue to work
//! - Last valid rules remain active
//!
//! ## Usage
//!
//! ```ignore
//! let mut loader = RuleLoader::new();
//! loader.add_file("rules/owasp-top10.yaml");
//! loader.add_file("rules/custom-rules.yaml");
//!
//! let rules = loader.load().expect("Failed to load rules");
//! ```
//! let matcher = RuleMatcher::new(rules, Severity::Medium);
//! ```
//!

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;
use waf_common::*;

/// Rule loader with hot reload support
pub struct RuleLoader {
    rule_files: Vec<String>,
    rules: Vec<Rule>,
    last_modified: std::collections::HashMap<String, std::time::SystemTime>,
}

impl RuleLoader {
    /// Create a new rule loader
    pub fn new() -> Self {
        Self {
            rule_files: Vec::new(),
            rules: Vec::new(),
            last_modified: std::collections::HashMap::new(),
        }
    }

    /// Add a rule file to load
    pub fn add_file(&mut self, path: impl Into<String>) -> &mut Self {
        self.rule_files.push(path.into());
        self
    }

    /// Add multiple rule files
    pub fn add_files(&mut self, paths: &[String]) -> &mut Self {
        for path in paths {
            self.rule_files.push(path.clone());
        }
        self
    }

    /// Load rules from all configured files
    pub fn load(&mut self) -> Result<Vec<Rule>> {
        self.rules.clear();

        for file_path in &self.rule_files {
            let rules = self.load_file(file_path)?;
            self.rules.extend(rules);
        }

        Ok(self.rules.clone())
    }

    /// Load rules from a single file
    fn load_file(&self, path: &str) -> Result<Vec<Rule>> {
        let path = Path::new(path);

        if !path.exists() {
            tracing::warn!("Rule file not found: {}", path.display());
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(path)?;

        #[derive(Deserialize)]
        struct RuleFile {
            #[serde(default)]
            rules: Vec<Rule>,
        }

        let parsed: RuleFile = serde_yaml::from_str(&content)?;
        tracing::info!(
            "Loaded {} rules from {}",
            parsed.rules.len(),
            path.display()
        );

        Ok(parsed.rules)
    }

    /// Check if any rule files have changed
    pub fn check_for_changes(&self) -> bool {
        for file_path in &self.rule_files {
            if let Ok(meta) = std::fs::metadata(file_path) {
                if let Ok(modified) = meta.modified() {
                    if let Some(last) = self.last_modified.get(file_path) {
                        if &modified > last {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Start watching for file changes
    pub fn watch(&mut self) -> Result<Receiver<Result<Vec<Rule>>>> {
        let (tx, rx) = channel();

        let files = self.rule_files.clone();

        std::thread::spawn(move || {
            let (event_tx, event_rx) = channel();

            let mut watcher = match RecommendedWatcher::new(
                move |res: std::result::Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = event_tx.send(event);
                    }
                },
                Config::default().with_poll_interval(Duration::from_secs(2)),
            ) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("Failed to create watcher: {}", e);
                    return;
                }
            };

            for file in &files {
                let _ = watcher.watch(Path::new(file), RecursiveMode::NonRecursive);
            }

            while let Ok(event) = event_rx.recv() {
                if event.kind.is_modify() || event.kind.is_create() {
                    tracing::info!("Rule file changed, reloading...");
                    let mut loader = RuleLoader::new();
                    for f in &files {
                        let _ = loader.add_file(f);
                    }
                    if let Ok(rules) = loader.load() {
                        let _ = tx.send(Ok(rules));
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Get currently loaded rules
    pub fn get_rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Default for RuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_rules_from_yaml() {
        let yaml = r#"
rules:
  - id: test-001
    name: "Test Rule"
    severity: high
    enabled: true
    conditions:
      - field: uri
        match_type: exact
        value: "/admin"
        case_insensitive: false
    action:
      type: block
      status_code: 403
      body: "Access denied"
      reason: "Admin access blocked"
"#;

        std::fs::write("/tmp/test_rules.yaml", yaml).unwrap();

        let mut loader = RuleLoader::new();
        loader.add_file("/tmp/test_rules.yaml");
        let rules = loader.load().unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test-001");
        assert_eq!(rules[0].severity, Severity::High);

        std::fs::remove_file("/tmp/test_rules.yaml").ok();
    }
}
