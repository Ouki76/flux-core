//! GeoIP routing against a real MaxMind database.
//!
//! The matcher had no test fixture at all, so the whole rule type was untested: a
//! `geoip` rule could have matched nothing, or everything, and the suite would not have
//! noticed. The fixture is MaxMind's own published test database (CC0), 18 KiB, and the
//! addresses below are the ones its documentation uses.

use flux_router::geoip::GeoIpMatcher;
use std::net::IpAddr;

fn fixture() -> GeoIpMatcher {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/GeoIP2-City-Test.mmdb"
    );
    let mut m = GeoIpMatcher::new();
    m.load_file(path)
        .unwrap_or_else(|e| panic!("load {path}: {e}"));
    m
}

#[test]
fn known_addresses_match_their_country() {
    let m = fixture();
    let cases = [
        ("81.2.69.142", "GB"),
        ("216.160.83.56", "US"),
        ("89.160.20.128", "SE"),
        ("2.125.160.216", "GB"),
    ];
    for (ip, code) in cases {
        let addr: IpAddr = ip.parse().unwrap();
        assert!(m.matches_country(addr, code), "{ip} should be {code}");
    }
}

#[test]
fn a_wrong_country_does_not_match() {
    let m = fixture();
    let addr: IpAddr = "81.2.69.142".parse().unwrap();
    assert!(!m.matches_country(addr, "US"));
    assert!(!m.matches_country(addr, "CN"));
}

#[test]
fn the_country_code_is_case_insensitive() {
    let m = fixture();
    let addr: IpAddr = "81.2.69.142".parse().unwrap();
    assert!(m.matches_country(addr, "gb"));
    assert!(m.matches_country(addr, "Gb"));
}

#[test]
fn an_address_outside_the_database_matches_nothing() {
    let m = fixture();
    // Reserved documentation range, absent from every real database.
    let addr: IpAddr = "192.0.2.1".parse().unwrap();
    for code in ["US", "GB", "SE", "CN", "RU"] {
        assert!(!m.matches_country(addr, code), "{code} must not match");
    }
}

#[test]
fn an_unloaded_matcher_matches_nothing_instead_of_panicking() {
    let m = GeoIpMatcher::new();
    let addr: IpAddr = "81.2.69.142".parse().unwrap();
    assert!(!m.matches_country(addr, "GB"));
}

#[test]
fn a_missing_or_corrupt_file_is_an_error_not_a_silent_empty_match() {
    let mut m = GeoIpMatcher::new();
    assert!(m.load_file("/nonexistent/geoip.mmdb").is_err());
    assert!(m.load_bytes(b"not a database".to_vec()).is_err());
}

/// A `geoip` rule is only useful if the router consults the database. Without a
/// registry the rule must match nothing; with one loaded it must match by country.
#[test]
fn a_geoip_rule_routes_by_country_and_only_with_a_registry() {
    use flux_router::geoip::GeoIpRegistry;
    use flux_router::rule::Rule;
    use flux_types::{NetworkType, SessionMeta, TargetAddress};

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/GeoIP2-City-Test.mmdb"
    );
    let registry = GeoIpRegistry::new();
    registry.load(path).expect("load registry");

    let rule = Rule {
        geoip: vec!["GB".to_string()],
        ..Rule::default()
    };

    let meta = |ip: &str| {
        SessionMeta::new(
            "127.0.0.1:40000".parse().unwrap(),
            TargetAddress::Ip(ip.parse().unwrap()),
            "in",
            NetworkType::Tcp,
        )
    };
    let gb = meta("81.2.69.142:443");
    let us = meta("216.160.83.56:443");

    assert!(
        rule.matches_with_context(&gb, None, Some(&registry), None),
        "a GB address must match a GB rule"
    );
    assert!(
        !rule.matches_with_context(&us, None, Some(&registry), None),
        "a US address must not match a GB rule"
    );
    assert!(
        !rule.matches_with_context(&gb, None, None, None),
        "with no database loaded a geoip rule must match nothing rather than everything"
    );
}
