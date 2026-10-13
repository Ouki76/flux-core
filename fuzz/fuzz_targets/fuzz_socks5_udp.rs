#![no_main]
use libfuzzer_sys::fuzz_target;
use flux_types::TargetAddress;

fuzz_target!(|data: &[u8]| {
    let src = TargetAddress::Ip("127.0.0.1:1000".parse().unwrap());
    let _ = flux_protocol::udp::decode_socks5_udp(src, data.to_vec().into());
});
