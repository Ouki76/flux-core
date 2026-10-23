//! Decodes hex dumps of mKCP datagrams, so a foreign peer's bytes can be read
//! instead of guessed at. Input: one `LEN HEX` or bare `HEX` line per datagram.
fn main() {
    let obfs = match std::env::args().nth(1).as_deref() {
        Some("none") => flux_transport::KcpObfs::None,
        _ => flux_transport::KcpObfs::Srtp,
    };
    for line in std::io::stdin().lines().map_while(Result::ok) {
        let hex = line.split_whitespace().last().unwrap_or("").trim();
        if hex.is_empty() {
            continue;
        }
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect();
        println!("{}", flux_transport::kcp::debug_parse(obfs, &bytes));
    }
}
