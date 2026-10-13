#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = flux_dns::wire::DnsMessage::validate_response(data, 0x1234);
    let _ = flux_dns::wire::DnsMessage::parse_a_record(data);
    let _ = flux_dns::wire::DnsMessage::parse_aaaa_record(data);
    let _ = flux_dns::wire::DnsMessage::parse_ip_record(data);
});
