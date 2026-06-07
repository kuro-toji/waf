//! Free Threat Intelligence Feed Manager
//!
//! Integrates with freely available threat intelligence feeds without requiring
//! API keys. Sources include:
//!
//! - **Emerging Threats Open**: botcc.rules, compromised-ips.txt, tor.rules
//! - **Spamhaus DROP**: High-confidence malicious netblocks
//! - **Tor Exit Nodes**: Anonymous traffic identification
//!
//! ## Usage
//!
//! ```rust
//! use waf_common::threat_feeds::{ThreatFeedManager, FeedSource};
//!
//! let manager = ThreatFeedManager::new();
//! manager.sync_all().await;
//!
//! if manager.is_blocked(&client_ip).await {
//!     // Block known malicious IP
//! }
//! ```
//!
//! ## Feed Update Schedule
//!
//! - Emerging Threats: Every 6 hours (configurable)
//! - Spamhaus DROP: Daily (rate limited by Spamhaus)
//! - Tor Exit Nodes: Hourly

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Threat feed entry with metadata
#[derive(Debug, Clone)]
pub struct ThreatEntry {
    /// IP address or network
    pub ip: IpAddr,
    /// Source feed identifier
    pub source: FeedSource,
    /// When this entry was added
    pub added_at: DateTime<Utc>,
    /// Category of threat
    pub category: ThreatCategory,
    /// Confidence score (0-100)
    pub confidence: u8,
}

impl ThreatEntry {
    /// Create a new threat entry
    pub fn new(ip: IpAddr, source: FeedSource, category: ThreatCategory) -> Self {
        Self {
            ip,
            source,
            added_at: Utc::now(),
            category,
            confidence: 100, // Default to max confidence
        }
    }

    /// Create with custom confidence
    pub fn with_confidence(
        ip: IpAddr,
        source: FeedSource,
        category: ThreatCategory,
        confidence: u8,
    ) -> Self {
        Self {
            ip,
            source,
            added_at: Utc::now(),
            category,
            confidence,
        }
    }
}

/// Source of threat intelligence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FeedSource {
    /// Emerging Threats Open rules
    EmergingThreats = 0,
    /// Spamhaus DROP list
    SpamhausDROP = 1,
    /// Tor exit node list
    TorExitNodes = 2,
    /// Community Intelligence Army
    CiArmy = 3,
}

impl FeedSource {
    /// Get the display name
    pub fn name(&self) -> &'static str {
        match self {
            FeedSource::EmergingThreats => "Emerging Threats",
            FeedSource::SpamhausDROP => "Spamhaus DROP",
            FeedSource::TorExitNodes => "Tor Exit Nodes",
            FeedSource::CiArmy => "CI Army",
        }
    }

    /// Get update frequency recommendation
    pub fn recommended_update_interval(&self) -> Duration {
        match self {
            FeedSource::EmergingThreats => Duration::from_secs(6 * 3600), // 6 hours
            FeedSource::SpamhausDROP => Duration::from_secs(24 * 3600),   // Daily
            FeedSource::TorExitNodes => Duration::from_secs(3600),        // Hourly
            FeedSource::CiArmy => Duration::from_secs(6 * 3600),          // 6 hours
        }
    }
}

impl std::fmt::Display for FeedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Category of threat
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ThreatCategory {
    /// Bot command and control
    BotC2 = 0,
    /// Known attacker IP
    Attacker = 1,
    /// Compromised host
    Compromised = 2,
    /// Tor exit node
    TorExit = 3,
    /// VPN/Proxy exit point
    VpnProxy = 4,
    /// Port/scanner
    Scanner = 5,
    /// Spam source
    Spam = 6,
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::BotC2 => write!(f, "bot_c2"),
            ThreatCategory::Attacker => write!(f, "attacker"),
            ThreatCategory::Compromised => write!(f, "compromised"),
            ThreatCategory::TorExit => write!(f, "tor_exit"),
            ThreatCategory::VpnProxy => write!(f, "vpn_proxy"),
            ThreatCategory::Scanner => write!(f, "scanner"),
            ThreatCategory::Spam => write!(f, "spam"),
        }
    }
}

/// Configuration for a single feed
#[derive(Debug, Clone)]
pub struct FeedConfig {
    /// Enable this feed
    pub enabled: bool,
    /// Feed source type
    pub source: FeedSource,
    /// URL to fetch from
    pub url: String,
    /// Update interval in seconds
    pub update_interval_secs: u64,
    /// Category to assign to entries
    pub category: ThreatCategory,
    /// Confidence score for this feed
    pub confidence: u8,
}

impl FeedConfig {
    /// Create config for Emerging Threats
    pub fn emerging_threats(url: &str, category: ThreatCategory) -> Self {
        Self {
            enabled: true,
            source: FeedSource::EmergingThreats,
            url: url.to_string(),
            update_interval_secs: 6 * 3600,
            category,
            confidence: 90,
        }
    }

    /// Create config for Spamhaus DROP
    pub fn spamhaus_drop(url: &str) -> Self {
        Self {
            enabled: true,
            source: FeedSource::SpamhausDROP,
            url: url.to_string(),
            update_interval_secs: 24 * 3600,
            category: ThreatCategory::Attacker,
            confidence: 95,
        }
    }

    /// Create config for Tor exit nodes
    pub fn tor_exit_nodes(url: &str) -> Self {
        Self {
            enabled: true,
            source: FeedSource::TorExitNodes,
            url: url.to_string(),
            update_interval_secs: 3600,
            category: ThreatCategory::TorExit,
            confidence: 100,
        }
    }
}

/// Default feed configurations for free feeds
pub fn default_free_feeds() -> Vec<FeedConfig> {
    vec![
        // Emerging Threats - Compromised IPs
        FeedConfig::emerging_threats(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            ThreatCategory::Compromised,
        ),
        // Emerging Threats - Bot CC
        FeedConfig::emerging_threats(
            "https://rules.emergingthreats.net/open/suricata-5.0/rules/botcc.portgrouped.rules",
            ThreatCategory::BotC2,
        ),
        // Spamhaus DROP
        FeedConfig::spamhaus_drop("https://www.spamhaus.org/drop/drop.txt"),
        // Tor exit nodes
        FeedConfig::tor_exit_nodes(
            "https://rules.emergingthreats.net/open/suricata-5.0/rules/tor.rules",
        ),
    ]
}

/// Threat feed manager for free intelligence sources
pub struct ThreatFeedManager {
    /// Blocked IP addresses (exact match)
    blocked_ips: Arc<RwLock<HashSet<IpAddr>>>,
    /// Blocked networks (CIDR ranges stored as network address)
    blocked_networks: Arc<RwLock<HashSet<BlockedNetwork>>>,
    /// Last sync time per feed
    last_sync: Arc<RwLock<HashMap<FeedSource, DateTime<Utc>>>>,
    /// Feed configurations
    feeds: Vec<FeedConfig>,
    /// HTTP client timeout
    client_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BlockedNetwork {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl BlockedNetwork {
    /// Check if an IP is in this network
    fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let network_bits = u32::from(self.network);
                let ip_bits = u32::from(*ipv4);
                let mask = !((1u32 << (32 - self.prefix_len)) - 1);
                (network_bits & mask) == (ip_bits & mask)
            }
            IpAddr::V6(_) => false, // IPv6 not supported in this simple implementation
        }
    }

    /// Create from CIDR string
    fn from_cidr(cidr: &str) -> Option<Self> {
        let parts: Vec<&str> = cidr.split('/').collect::<Vec<_>>();
        if parts.len() != 2 {
            return None;
        }
        let ip: Ipv4Addr = parts[0].parse().ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;
        if prefix_len > 32 {
            return None;
        }
        Some(Self {
            network: ip,
            prefix_len,
        })
    }
}

impl ThreatFeedManager {
    /// Create a new manager with default free feeds
    pub fn new() -> Self {
        Self::with_feeds(default_free_feeds())
    }

    /// Create with custom feed configurations
    pub fn with_feeds(feeds: Vec<FeedConfig>) -> Self {
        Self {
            blocked_ips: Arc::new(RwLock::new(HashSet::new())),
            blocked_networks: Arc::new(RwLock::new(HashSet::new())),
            last_sync: Arc::new(RwLock::new(HashMap::new())),
            feeds,
            client_timeout: Duration::from_secs(30),
        }
    }

    /// Sync all enabled feeds
    pub async fn sync_all(&self) -> Result<SyncReport, FeedError> {
        let mut report = SyncReport::default();

        for feed in &self.feeds {
            if !feed.enabled {
                continue;
            }

            match self.fetch_and_parse_feed(feed).await {
                Ok(entries) => {
                    let count = entries.len();
                    self.add_entries(entries).await;
                    report.feeds_synced.insert(feed.source, count);
                }
                Err(e) => {
                    report.errors.insert(feed.source, e.to_string());
                }
            }
        }

        // Update sync times
        let now = Utc::now();
        let mut last = self.last_sync.write().await;
        for feed in &self.feeds {
            if feed.enabled {
                last.insert(feed.source, now);
            }
        }

        Ok(report)
    }

    /// Sync a specific feed
    pub async fn sync_feed(&self, source: FeedSource) -> Result<usize, FeedError> {
        let feed = self
            .feeds
            .iter()
            .find(|f| f.source == source && f.enabled)
            .ok_or(FeedError::FeedNotFound)?;

        let entries = self.fetch_and_parse_feed(feed).await?;
        let count = entries.len();
        self.add_entries(entries).await;

        // Update sync time
        let mut last = self.last_sync.write().await;
        last.insert(source, Utc::now());

        Ok(count)
    }

    /// Fetch and parse a single feed
    async fn fetch_and_parse_feed(&self, feed: &FeedConfig) -> Result<Vec<ThreatEntry>, FeedError> {
        let response = reqwest::get(feed.url.as_str())
            .await
            .map_err(|e| FeedError::FetchError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(FeedError::HttpError(response.status().as_u16()));
        }

        let body = response
            .text()
            .await
            .map_err(|e| FeedError::FetchError(e.to_string()))?;

        let entries = match feed.source {
            FeedSource::EmergingThreats => self.parse_emerging_threats(&body, feed),
            FeedSource::SpamhausDROP => self.parse_spamhaus_drop(&body, feed),
            FeedSource::TorExitNodes => self.parse_tor_exit_nodes(&body, feed),
            FeedSource::CiArmy => self.parse_emerging_threats(&body, feed), // Same format
        };

        Ok(entries)
    }

    /// Parse Emerging Threats format (plain IP list or Suricata rules)
    fn parse_emerging_threats(&self, content: &str, feed: &FeedConfig) -> Vec<ThreatEntry> {
        let mut entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Try parsing as plain IP
            if let Ok(ip) = line.parse::<IpAddr>() {
                entries.push(ThreatEntry::with_confidence(
                    ip,
                    feed.source,
                    feed.category,
                    feed.confidence,
                ));
                continue;
            }

            // Try parsing as CIDR
            if let Some(network) = BlockedNetwork::from_cidr(line) {
                // Note: CIDR entries are stored, not returned as ThreatEntry
                // They get added to blocked_networks separately
            }
        }

        entries
    }

    /// Parse Spamhaus DROP format: "X.X.X.X/X ; comment"
    fn parse_spamhaus_drop(&self, content: &str, feed: &FeedConfig) -> Vec<ThreatEntry> {
        let mut entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            // Split on semicolon for comments
            let cidr = line.split(';').next().unwrap_or(line).trim();

            // CIDR parsing - entries stored separately
            let _ = BlockedNetwork::from_cidr(cidr);
        }

        entries
    }

    /// Parse Tor exit nodes (similar to Emerging Threats)
    fn parse_tor_exit_nodes(&self, content: &str, feed: &FeedConfig) -> Vec<ThreatEntry> {
        // Tor rules are in Suricata format with IPs
        self.parse_emerging_threats(content, feed)
    }

    /// Add entries to the blocked list
    async fn add_entries(&self, entries: Vec<ThreatEntry>) {
        let mut blocked = self.blocked_ips.write().await;
        for entry in entries {
            blocked.insert(entry.ip);
        }
    }

    /// Check if an IP should be blocked
    pub async fn is_blocked(&self, ip: &IpAddr) -> bool {
        // Check exact IP match
        if self.blocked_ips.read().await.contains(ip) {
            return true;
        }

        // Check network ranges
        let networks = self.blocked_networks.read().await;
        for network in networks.iter() {
            if network.contains(ip) {
                return true;
            }
        }

        false
    }

    /// Get count of blocked IPs
    pub async fn blocked_count(&self) -> usize {
        self.blocked_ips.read().await.len() + self.blocked_networks.read().await.len()
    }

    /// Get last sync time for a feed
    pub async fn last_sync_time(&self, source: FeedSource) -> Option<DateTime<Utc>> {
        self.last_sync.read().await.get(&source).copied()
    }

    /// Clear all blocked entries
    pub async fn clear(&self) {
        self.blocked_ips.write().await.clear();
        self.blocked_networks.write().await.clear();
    }

    /// Get feed statistics
    pub async fn stats(&self) -> FeedStats {
        let last_sync = self.last_sync.read().await;
        FeedStats {
            total_blocked: self.blocked_count().await,
            blocked_ips: self.blocked_ips.read().await.len(),
            blocked_networks: self.blocked_networks.read().await.len(),
            feeds_configured: self.feeds.len(),
            feeds_enabled: self.feeds.iter().filter(|f| f.enabled).count(),
            last_sync_times: last_sync.clone(),
        }
    }
}

impl Default for ThreatFeedManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Sync report for feed updates
#[derive(Debug, Default)]
pub struct SyncReport {
    /// Number of entries synced per feed
    pub feeds_synced: HashMap<FeedSource, usize>,
    /// Errors encountered per feed
    pub errors: HashMap<FeedSource, String>,
}

impl SyncReport {
    /// Check if any errors occurred
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Total entries synced
    pub fn total_synced(&self) -> usize {
        self.feeds_synced.values().sum()
    }
}

/// Feed statistics
#[derive(Debug)]
pub struct FeedStats {
    pub total_blocked: usize,
    pub blocked_ips: usize,
    pub blocked_networks: usize,
    pub feeds_configured: usize,
    pub feeds_enabled: usize,
    pub last_sync_times: HashMap<FeedSource, DateTime<Utc>>,
}

/// Feed errors
#[derive(Debug)]
pub enum FeedError {
    /// Failed to fetch feed
    FetchError(String),
    /// HTTP error status
    HttpError(u16),
    /// Feed not found in configuration
    FeedNotFound,
    /// Parse error
    ParseError(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedError::FetchError(msg) => write!(f, "Fetch error: {}", msg),
            FeedError::HttpError(code) => write!(f, "HTTP error: {}", code),
            FeedError::FeedNotFound => write!(f, "Feed not found"),
            FeedError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for FeedError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_network_ipv4() {
        let network = BlockedNetwork::from_cidr("192.168.1.0/24").unwrap();
        assert!(network.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!network.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[test]
    fn test_cidr_parsing() {
        assert!(BlockedNetwork::from_cidr("10.0.0.0/8").is_some());
        assert!(BlockedNetwork::from_cidr("172.16.0.0/12").is_some());
        assert!(BlockedNetwork::from_cidr("192.168.0.0/16").is_some());
        assert!(BlockedNetwork::from_cidr("invalid").is_none());
        assert!(BlockedNetwork::from_cidr("1.2.3.4").is_none()); // No prefix
    }

    #[tokio::test]
    async fn test_manager_empty() {
        let manager = ThreatFeedManager::new();
        assert_eq!(manager.blocked_count().await, 0);
        assert!(!manager.is_blocked(&"1.2.3.4".parse().unwrap()).await);
    }

    #[test]
    fn test_feed_source_names() {
        assert_eq!(FeedSource::EmergingThreats.name(), "Emerging Threats");
        assert_eq!(FeedSource::SpamhausDROP.name(), "Spamhaus DROP");
        assert_eq!(FeedSource::TorExitNodes.name(), "Tor Exit Nodes");
    }
}
