#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut rs = flux_router::RuleSet::default();
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        rs.parse_rule_line(line);
    }
    let _ = rs.compile();
});
