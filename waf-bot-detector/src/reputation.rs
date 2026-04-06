//! IP Reputation Database
//!
//! Manages IP reputation and known bot/TOR/VPN lists.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::RwLock;

/// IP reputation entry
#[derive(Debug, Clone)]
pub struct IpReputation {
    pub ip: String,
    pub score: u8,
    pub category: ReputationCategory,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub attack_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReputationCategory {
    Clean,
    Suspicious,
    Malicious,
    Tor,
    Vpn,
    Proxy,
    Bot,
}

impl Default for ReputationCategory {
    fn default() -> Self {
        ReputationCategory::Clean
    }
}

/// IP reputation database
pub struct ReputationDatabase {
    entries: RwLock<HashMap<String, IpReputation>>,
    /// Known TOR exit node IPs
    tor_nodes: RwLock<Vec<String>>,
    /// Known VPN provider IP ranges
    vpn_ranges: RwLock<Vec<String>>,
}

impl ReputationDatabase {
    /// Create a new reputation database
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            tor_nodes: RwLock::new(Vec::new()),
            vpn_ranges: RwLock::new(Vec::new()),
        }
    }

    /// Get reputation for an IP
    pub fn get_reputation(&self, ip: &str) -> Option<IpReputation> {
        // Check TOR first
        if self.is_tor_node(ip) {
            return Some(IpReputation {
                ip: ip.to_string(),
                score: 100,
                category: ReputationCategory::Tor,
                last_seen: Utc::now(),
                first_seen: Utc::now(),
                attack_count: 0,
            });
        }

        // Check entries
        let entries = self.entries.read().unwrap();
        entries.get(ip).cloned()
    }

    /// Check if IP is a known TOR node
    pub fn is_tor_node(&self, ip: &str) -> bool {
        let tor = self.tor_nodes.read().unwrap();
        tor.iter()
            .any(|node| ip == node || ip.starts_with(&node[..node.rfind('.').unwrap_or(0)]))
    }

    /// Add TOR exit node
    pub fn add_tor_node(&self, ip: &str) {
        let mut tor = self.tor_nodes.write().unwrap();
        if !tor.contains(&ip.to_string()) {
            tor.push(ip.to_string());
        }
    }

    /// Add VPN range
    pub fn add_vpn_range(&self, range: &str) {
        let mut vpn = self.vpn_ranges.write().unwrap();
        if !vpn.contains(&range.to_string()) {
            vpn.push(range.to_string());
        }
    }

    /// Update reputation for an IP
    pub fn update_reputation(&self, ip: &str, score_delta: i16, category: ReputationCategory) {
        let mut entries = self.entries.write().unwrap();

        let entry = entries
            .entry(ip.to_string())
            .or_insert_with(|| IpReputation {
                ip: ip.to_string(),
                score: 50,
                category: ReputationCategory::Clean,
                last_seen: Utc::now(),
                first_seen: Utc::now(),
                attack_count: 0,
            });

        // Update score (clamp between 0 and 100)
        entry.score = (entry.score as i16 + score_delta).clamp(0, 100) as u8;
        entry.last_seen = Utc::now();

        if score_delta > 0 {
            entry.attack_count += 1;
        }

        // Update category based on score
        if entry.score >= 80 {
            entry.category = ReputationCategory::Malicious;
        } else if entry.score >= 50 {
            entry.category = ReputationCategory::Suspicious;
        } else {
            entry.category = ReputationCategory::Clean;
        }

        // If explicit category provided, use it
        if category != ReputationCategory::Clean {
            entry.category = category;
        }
    }

    /// Get top attackers
    pub fn get_top_attackers(&self, limit: usize) -> Vec<IpReputation> {
        let entries = self.entries.read().unwrap();
        let mut sorted: Vec<_> = entries.values().collect();
        sorted.sort_by(|a, b| b.attack_count.cmp(&a.attack_count));
        sorted.into_iter().take(limit).cloned().collect()
    }

    /// Get malicious IPs
    pub fn get_malicious_ips(&self) -> Vec<String> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|(_, e)| e.category == ReputationCategory::Malicious || e.score >= 80)
            .map(|(ip, _)| ip.clone())
            .collect()
    }

    /// Clear old entries
    pub fn cleanup_old_entries(&self, older_than: chrono::Duration) {
        let cutoff = Utc::now() - older_than;
        let mut entries = self.entries.write().unwrap();
        entries.retain(|_, e| e.last_seen > cutoff);
    }
}

impl Default for ReputationDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_update() {
        let db = ReputationDatabase::new();

        db.update_reputation("192.168.1.1", 30, ReputationCategory::Suspicious);

        let rep = db.get_reputation("192.168.1.1");
        assert!(rep.is_some());
        assert_eq!(rep.unwrap().score, 80);
    }

    #[test]
    fn test_tor_node_detection() {
        let db = ReputationDatabase::new();
        db.add_tor_node("192.168.1.100");

        assert!(db.is_tor_node("192.168.1.100"));
        assert!(!db.is_tor_node("192.168.1.1"));
    }
}
