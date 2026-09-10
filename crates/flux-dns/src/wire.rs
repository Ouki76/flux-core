use std::net::Ipv4Addr;
use flux_types::{FluxError, FluxResult};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;

pub struct DnsMessage;

impl DnsMessage {
    /// Builds a standard DNS query packet in binary wireformat.
    pub fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        // Header
        let tx_id = rand::random::<u16>();
        buf.extend_from_slice(&tx_id.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD = 1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        // Question: QNAME
        for label in domain.split('.') {
            if !label.is_empty() {
                buf.push(label.len() as u8);
                buf.extend_from_slice(label.as_bytes());
            }
        }
        buf.push(0x00); // Root label null terminator

        // QTYPE and QCLASS (IN = 1)
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());

        buf
    }

    /// Parses the first A (IPv4) record from a DNS response in wireformat.
    pub fn parse_a_record(data: &[u8]) -> FluxResult<Ipv4Addr> {
        if data.len() < 12 {
            return Err(FluxError::Dns("DNS response too short".into()));
        }

        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        if ancount == 0 {
            return Err(FluxError::Dns("DNS response contains 0 answers".into()));
        }

        // Skip Header (12 bytes)
        let mut pos = 12;

        // Skip Question section
        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            if len == 0 {
                break;
            }
            if (len & 0xC0) == 0xC0 {
                // Pointer in question
                pos += 1;
                break;
            }
            pos += len;
        }
        pos += 4; // Skip QTYPE (2) and QCLASS (2)

        // Parse Answer section
        for _ in 0..ancount {
            if pos >= data.len() {
                break;
            }

            // Name (either labels or compression pointer)
            if (data[pos] & 0xC0) == 0xC0 {
                pos += 2; // Pointer
            } else {
                while pos < data.len() && data[pos] != 0 {
                    pos += 1 + (data[pos] as usize);
                }
                pos += 1; // null terminator
            }

            if pos + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let _ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > data.len() {
                break;
            }

            if rtype == QTYPE_A && rdlength == 4 {
                let ip_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
                return Ok(Ipv4Addr::from(ip_bytes));
            }

            pos += rdlength;
        }

        Err(FluxError::Dns("no valid A record found in DNS response".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_dns_query() {
        let query = DnsMessage::build_query("example.com", QTYPE_A);
        assert!(query.len() > 12);
        assert_eq!(query[4], 0);
        assert_eq!(query[5], 1); // 1 question
    }
}
