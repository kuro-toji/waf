//! Community Rules Loader
//!
//! Loads and manages community-contributed rules from the rules directory.
//! Follows OWASP CRS model with GitHub-based collaboration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::info;

/// Community rule metadata from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityRuleMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub author: String,
    pub version: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub rules: Vec<RulePattern>,
    pub tests: Option<Vec<TestCase>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePattern {
    pub pattern: String,
    #[serde(rename = "type")]
    pub pattern_type: Option<String>,
    pub confidence: u8,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub input: String,
    pub expected_match: bool,
}

/// Community rules index
pub struct CommunityRulesIndex {
    /// Rules by category
    by_category: HashMap<String, Vec<String>>,
    /// Rules by severity. Parallel to `by_category`; population deferred
    /// until a severity-aware indexer lands.
    #[allow(dead_code)]
    by_severity: HashMap<String, Vec<String>>,
    /// All rule IDs
    all_ids: Vec<String>,
}

impl CommunityRulesIndex {
    /// Create new index
    pub fn new() -> Self {
        Self {
            by_category: HashMap::new(),
            by_severity: HashMap::new(),
            all_ids: Vec::new(),
        }
    }

    /// Load rules index from directory
    pub async fn load_from_dir(dir: &Path) -> Result<Self, std::io::Error> {
        let mut index = Self::new();

        if !dir.exists() {
            info!("No community rules directory found: {:?}", dir);
            return Ok(index);
        }

        let mut entries = fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                let category = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("other")
                    .to_string();

                // Scan directory for YAML files
                if let Ok(mut files) = fs::read_dir(&path).await {
                    while let Some(file) = files.next_entry().await? {
                        let file_path = file.path();
                        if file_path
                            .extension()
                            .is_some_and(|e| e == "yaml" || e == "yml")
                        {
                            if let Some(rule_id) = Self::extract_rule_id(&file_path).await {
                                index.all_ids.push(rule_id.clone());
                                index
                                    .by_category
                                    .entry(category.clone())
                                    .or_default()
                                    .push(rule_id);
                            }
                        }
                    }
                }
            }
        }

        info!(
            "Loaded {} community rules in {} categories",
            index.all_ids.len(),
            index.by_category.len()
        );

        Ok(index)
    }

    /// Extract rule ID from file content (async)
    async fn extract_rule_id(path: &Path) -> Option<String> {
        let content = fs::read_to_string(path).await.ok()?;
        Self::parse_rule_id_from_content(&content)
    }

    /// Parse rule ID from YAML content
    fn parse_rule_id_from_content(content: &str) -> Option<String> {
        serde_yaml::from_str::<CommunityRuleMetadata>(content)
            .ok()
            .map(|m| m.id)
    }

    /// Get rule count
    pub fn count(&self) -> usize {
        self.all_ids.len()
    }

    /// Get rules by category
    pub fn get_by_category(&self, category: &str) -> &[String] {
        self.by_category
            .get(category)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all categories
    pub fn categories(&self) -> Vec<&str> {
        self.by_category.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for CommunityRulesIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_load_rules_index() {
        // Create temp directory with sample rule
        let dir = TempDir::new().unwrap();
        let rules_dir = dir.path().join("rules");
        std::fs::create_dir_all(rules_dir.join("sqli")).unwrap();

        let rule_content = r#"
id: community-test-001
name: "Test Rule"
description: "Test description"
severity: high
category: sqli
author: test
version: "1.0"
rules:
  - pattern: "test"
    confidence: 80
"#;

        let mut file = std::fs::File::create(rules_dir.join("sqli/test.yaml")).unwrap();
        file.write_all(rule_content.as_bytes()).unwrap();

        let index = CommunityRulesIndex::load_from_dir(&rules_dir)
            .await
            .unwrap();

        assert_eq!(index.count(), 1);
        assert_eq!(index.categories(), vec!["sqli"]);
        assert!(!index.get_by_category("sqli").is_empty());
    }
}
