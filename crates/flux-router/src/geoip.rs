use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
/// One GeoIP entry from the configuration: which database and which country.
pub struct GeoIpConfig {
    /// Path to the `.mmdb` file; `None` means the built-in default location.
    pub path: Option<String>,
    /// The ISO country code to match, e.g. `"RU"`.
    pub code: String,
}

#[derive(Default)]
/// Looks an address up in one MaxMind database.
pub struct GeoIpMatcher {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpMatcher {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a database from disk, replacing any previous one.
    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<(), maxminddb::MaxMindDbError> {
        let content = std::fs::read(path)
            .map_err(|e| maxminddb::MaxMindDbError::invalid_database(e.to_string()))?;
        let reader = maxminddb::Reader::from_source(content)?;
        self.reader = Some(reader);
        Ok(())
    }

    /// Loads a database already in memory, replacing any previous one.
    pub fn load_bytes(&mut self, bytes: Vec<u8>) -> Result<(), maxminddb::MaxMindDbError> {
        let reader = maxminddb::Reader::from_source(bytes)?;
        self.reader = Some(reader);
        Ok(())
    }

    /// Checks if the IP address belongs to the specified ISO country code (e.g., "RU", "CN", "US").
    /// Whether `ip` resolves to `target_code`. Case-insensitive; false when unloaded.
    pub fn matches_country(&self, ip: IpAddr, target_code: &str) -> bool {
        let Some(ref reader) = self.reader else {
            return false;
        };

        if let Ok(lookup) = reader.lookup(ip)
            && let Ok(Some(country)) = lookup.decode::<maxminddb::geoip2::Country>()
            && let Some(iso) = country.country.iso_code
        {
            return iso.eq_ignore_ascii_case(target_code);
        }
        false
    }
}

/// The process-wide GeoIP database, shared by every rule that needs it.
pub struct GeoIpRegistry {
    matchers: Arc<RwLock<Option<GeoIpMatcher>>>,
}

impl Default for GeoIpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            matchers: Arc::new(RwLock::new(None)),
        }
    }

    /// Loads the database at `path`, replacing any previous one.
    pub fn load(&self, path: &str) -> Result<(), String> {
        let mut matcher = GeoIpMatcher::new();
        matcher.load_file(path).map_err(|e| e.to_string())?;
        *self.matchers.write() = Some(matcher);
        Ok(())
    }

    /// Whether `ip` belongs to `country`; false when nothing is loaded.
    pub fn matches(&self, ip: IpAddr, country: &str) -> bool {
        if let Some(ref m) = *self.matchers.read() {
            m.matches_country(ip, country)
        } else {
            false
        }
    }
}
