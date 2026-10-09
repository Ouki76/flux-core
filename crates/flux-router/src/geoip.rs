use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GeoIpConfig {
    pub path: Option<String>,
    pub code: String,
}

#[derive(Default)]
pub struct GeoIpMatcher {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<(), maxminddb::MaxMindDbError> {
        let content = std::fs::read(path)
            .map_err(|e| maxminddb::MaxMindDbError::invalid_database(e.to_string()))?;
        let reader = maxminddb::Reader::from_source(content)?;
        self.reader = Some(reader);
        Ok(())
    }

    pub fn load_bytes(&mut self, bytes: Vec<u8>) -> Result<(), maxminddb::MaxMindDbError> {
        let reader = maxminddb::Reader::from_source(bytes)?;
        self.reader = Some(reader);
        Ok(())
    }

    /// Checks if the IP address belongs to the specified ISO country code (e.g., "RU", "CN", "US").
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

pub struct GeoIpRegistry {
    matchers: Arc<RwLock<Option<GeoIpMatcher>>>,
}

impl Default for GeoIpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpRegistry {
    pub fn new() -> Self {
        Self {
            matchers: Arc::new(RwLock::new(None)),
        }
    }

    pub fn load(&self, path: &str) -> Result<(), String> {
        let mut matcher = GeoIpMatcher::new();
        matcher.load_file(path).map_err(|e| e.to_string())?;
        *self.matchers.write() = Some(matcher);
        Ok(())
    }

    pub fn matches(&self, ip: IpAddr, country: &str) -> bool {
        if let Some(ref m) = *self.matchers.read() {
            m.matches_country(ip, country)
        } else {
            false
        }
    }
}
