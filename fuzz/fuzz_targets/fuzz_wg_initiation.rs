#![no_main]
use libfuzzer_sys::fuzz_target;
use flux_protocol::wireguard::{AwgConfig, WireGuardHandshake};
use x25519_dalek::StaticSecret;

fuzz_target!(|data: &[u8]| {
    let secret = StaticSecret::from([0x42u8; 32]);
    let awg = AwgConfig::default();
    let _ = WireGuardHandshake::respond_to_initiation(&secret, 42, &awg, data, None);
});
