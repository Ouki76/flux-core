use flux_types::{FluxError, FluxResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;

pub struct DnsMessage;

impl DnsMessage {
    /// Builds a standard DNS query packet in binary wireformat.
    pub fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
        Self::build_query_with_ecs(domain, qtype, None)
    }

    /// Builds a DNS query packet with optional EDNS0 Client Subnet (ECS, RFC 7871).
    pub fn build_query_with_ecs(
        domain: &str,
        qtype: u16,
        client_subnet: Option<ipnet::IpNet>,
    ) -> Vec<u8> {
        let tx_id = rand::random::<u16>();
        Self::build_query_with_ecs_id(domain, qtype, client_subnet, tx_id)
    }

    /// Builds a DNS query packet with specific Transaction ID and optional EDNS0 Client Subnet.
    pub fn build_query_with_ecs_id(
        domain: &str,
        qtype: u16,
        client_subnet: Option<ipnet::IpNet>,
        tx_id: u16,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        // Header
        buf.extend_from_slice(&tx_id.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD = 1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0

        let has_ecs = client_subnet.is_some();
        buf.extend_from_slice(&(if has_ecs { 1u16 } else { 0u16 }).to_be_bytes()); // ARCOUNT = 1 if ECS

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

        // Optional EDNS0 RR (RFC 7871 Client Subnet)
        if let Some(subnet) = client_subnet {
            buf.push(0x00); // Root domain name
            buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT (41)
            buf.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size (4096)
            buf.extend_from_slice(&0u32.to_be_bytes()); // TTL = extended RCODE + flags (0)

            let (family, prefix_len, addr_bytes) = match subnet {
                ipnet::IpNet::V4(v4) => {
                    let octets = v4.addr().octets();
                    let prefix = v4.prefix_len();
                    let bytes_needed = (prefix as usize).div_ceil(8);
                    (1u16, prefix, octets[..bytes_needed].to_vec())
                }
                ipnet::IpNet::V6(v6) => {
                    let octets = v6.addr().octets();
                    let prefix = v6.prefix_len();
                    let bytes_needed = (prefix as usize).div_ceil(8);
                    (2u16, prefix, octets[..bytes_needed].to_vec())
                }
            };

            let option_len = 2 + 1 + 1 + addr_bytes.len();
            let rdlength = 2 + 2 + option_len;
            buf.extend_from_slice(&(rdlength as u16).to_be_bytes());

            // ECS Option
            buf.extend_from_slice(&8u16.to_be_bytes()); // Option Code 8 = Client Subnet
            buf.extend_from_slice(&(option_len as u16).to_be_bytes());
            buf.extend_from_slice(&family.to_be_bytes());
            buf.push(prefix_len);
            buf.push(0x00); // Scope prefix length = 0 in query
            buf.extend_from_slice(&addr_bytes);
        }

        buf
    }

    /// Validates DNS response header:
    /// - Length >= 12
    /// - Matching Transaction ID
    /// - QR flag is 1 (response)
    /// - RCODE is 0 (NoError)
    pub fn validate_response(data: &[u8], expected_tx_id: u16) -> FluxResult<()> {
        if data.len() < 12 {
            return Err(FluxError::Dns("DNS response too short".into()));
        }
        let resp_id = u16::from_be_bytes([data[0], data[1]]);
        if resp_id != expected_tx_id {
            return Err(FluxError::Dns(format!(
                "mismatched DNS transaction ID: expected 0x{:04x}, got 0x{:04x}",
                expected_tx_id, resp_id
            )));
        }
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags & 0x8000) != 0;
        if !is_response {
            return Err(FluxError::Dns("DNS packet is not a response (QR=0)".into()));
        }
        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(FluxError::Dns(format!(
                "DNS query returned error RCODE {}",
                rcode
            )));
        }
        Ok(())
    }

    /// Single-pass parser that traverses questions and answers, returning the first matching IP (A or AAAA) with TTL.
    pub fn parse_ip_record_with_ttl(data: &[u8]) -> FluxResult<(IpAddr, u32)> {
        if data.len() < 12 {
            return Err(FluxError::Dns("DNS response too short".into()));
        }

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        if ancount == 0 {
            return Err(FluxError::Dns("DNS response contains 0 answers".into()));
        }

        let mut pos = 12;

        // Skip questions (qdcount)
        for _ in 0..qdcount {
            while pos < data.len() {
                let len = data[pos] as usize;
                pos += 1;
                if len == 0 {
                    break;
                }
                if (len & 0xC0) == 0xC0 {
                    pos += 1; // 2-byte pointer
                    break;
                }
                if pos + len > data.len() {
                    return Err(FluxError::Dns(
                        "malformed DNS packet: question label exceeds length".into(),
                    ));
                }
                pos += len;
            }
            if pos + 4 > data.len() {
                return Err(FluxError::Dns(
                    "malformed DNS packet: truncated question type/class".into(),
                ));
            }
            pos += 4; // Skip QTYPE (2) + QCLASS (2)
        }

        let mut first_v6: Option<(IpAddr, u32)> = None;

        // Parse Answer section in a single pass
        for _ in 0..ancount {
            if pos >= data.len() {
                break;
            }

            // Name: RFC 1035 label and pointer decompression traversal with step limit to prevent loops
            let mut steps = 0;
            while pos < data.len() && steps < 64 {
                steps += 1;
                let b = data[pos];
                if b == 0 {
                    pos += 1;
                    break;
                }
                if (b & 0xC0) == 0xC0 {
                    pos += 2;
                    break;
                }
                let label_len = b as usize;
                if pos + 1 + label_len > data.len() {
                    return Err(FluxError::Dns(
                        "malformed DNS packet: answer label exceeds length".into(),
                    ));
                }
                pos += 1 + label_len;
            }

            if pos + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let ttl =
                u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > data.len() {
                break;
            }

            if rtype == QTYPE_A && rdlength == 4 {
                let ip_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
                return Ok((IpAddr::V4(Ipv4Addr::from(ip_bytes)), ttl));
            } else if rtype == QTYPE_AAAA && rdlength == 16 && first_v6.is_none() {
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[pos..pos + 16]);
                first_v6 = Some((IpAddr::V6(Ipv6Addr::from(ip_bytes)), ttl));
            }

            pos += rdlength;
        }

        if let Some(v6) = first_v6 {
            return Ok(v6);
        }

        Err(FluxError::Dns(
            "no valid A or AAAA record found in DNS response".into(),
        ))
    }

    /// Single-pass parser that traverses questions and answers, returning the first matching IP (A or AAAA).
    pub fn parse_ip_record(data: &[u8]) -> FluxResult<IpAddr> {
        Self::parse_ip_record_with_ttl(data).map(|(ip, _)| ip)
    }

    /// Parses the first A (IPv4) record from a DNS response in wireformat.
    pub fn parse_a_record(data: &[u8]) -> FluxResult<Ipv4Addr> {
        let (ip, _) = Self::parse_specific_record_with_ttl(data, QTYPE_A)?;
        match ip {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err(FluxError::Dns("expected A record, got AAAA".into())),
        }
    }

    /// Parses the first AAAA (IPv6) record from a DNS response in wireformat.
    pub fn parse_aaaa_record(data: &[u8]) -> FluxResult<Ipv6Addr> {
        let (ip, _) = Self::parse_specific_record_with_ttl(data, QTYPE_AAAA)?;
        match ip {
            IpAddr::V6(v6) => Ok(v6),
            IpAddr::V4(_) => Err(FluxError::Dns("expected AAAA record, got A".into())),
        }
    }

    /// Single-pass parser that traverses questions and answers, returning the first record matching target_qtype.
    pub fn parse_specific_record_with_ttl(
        data: &[u8],
        target_qtype: u16,
    ) -> FluxResult<(IpAddr, u32)> {
        if data.len() < 12 {
            return Err(FluxError::Dns("DNS response too short".into()));
        }

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        if ancount == 0 {
            return Err(FluxError::Dns("DNS response contains 0 answers".into()));
        }

        let mut pos = 12;

        // Skip questions (qdcount)
        for _ in 0..qdcount {
            while pos < data.len() {
                let len = data[pos] as usize;
                pos += 1;
                if len == 0 {
                    break;
                }
                if (len & 0xC0) == 0xC0 {
                    pos += 1; // 2-byte pointer
                    break;
                }
                if pos + len > data.len() {
                    return Err(FluxError::Dns(
                        "malformed DNS packet: question label exceeds length".into(),
                    ));
                }
                pos += len;
            }
            if pos + 4 > data.len() {
                return Err(FluxError::Dns(
                    "malformed DNS packet: truncated question type/class".into(),
                ));
            }
            pos += 4; // Skip QTYPE (2) + QCLASS (2)
        }

        for _ in 0..ancount {
            if pos >= data.len() {
                break;
            }

            let mut steps = 0;
            while pos < data.len() && steps < 64 {
                steps += 1;
                let b = data[pos];
                if b == 0 {
                    pos += 1;
                    break;
                }
                if (b & 0xC0) == 0xC0 {
                    pos += 2;
                    break;
                }
                let label_len = b as usize;
                if pos + 1 + label_len > data.len() {
                    return Err(FluxError::Dns(
                        "malformed DNS packet: answer label exceeds length".into(),
                    ));
                }
                pos += 1 + label_len;
            }

            if pos + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ttl =
                u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > data.len() {
                break;
            }

            if rtype == target_qtype {
                if rtype == QTYPE_A && rdlength == 4 {
                    let ip_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
                    return Ok((IpAddr::V4(Ipv4Addr::from(ip_bytes)), ttl));
                } else if rtype == QTYPE_AAAA && rdlength == 16 {
                    let mut ip_bytes = [0u8; 16];
                    ip_bytes.copy_from_slice(&data[pos..pos + 16]);
                    return Ok((IpAddr::V6(Ipv6Addr::from(ip_bytes)), ttl));
                }
            }

            pos += rdlength;
        }

        Err(FluxError::Dns(format!(
            "no matching record with type {} found in DNS response",
            target_qtype
        )))
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

    #[test]
    fn test_build_query_with_ecs() {
        let subnet: ipnet::IpNet = "192.0.2.0/24".parse().unwrap();
        let query = DnsMessage::build_query_with_ecs("example.com", QTYPE_A, Some(subnet));
        assert!(query.len() > 30);
        assert_eq!(query[11], 1); // ARCOUNT = 1
        // Contains Option 8 (Client Subnet)
        assert!(query.windows(2).any(|w| w == [0x00, 0x08]));
    }

    #[test]
    fn test_parse_aaaa_record() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x12, 0x34]); // ID
        resp.extend_from_slice(&[0x81, 0x80]); // Flags: Response, NoError
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT: 1
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question: example.com
        resp.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        resp.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());

        // Answer
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&16u16.to_be_bytes());
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        resp.extend_from_slice(&ip.octets());

        let parsed = DnsMessage::parse_aaaa_record(&resp).unwrap();
        assert_eq!(parsed, ip);

        let parsed_ip = DnsMessage::parse_ip_record(&resp).unwrap();
        assert_eq!(parsed_ip, IpAddr::V6(ip));
    }

    #[test]
    fn test_parse_dual_a_and_aaaa_records() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x12, 0x34]); // ID
        resp.extend_from_slice(&[0x81, 0x80]); // Flags: Response, NoError
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
        resp.extend_from_slice(&[0x00, 0x02]); // ANCOUNT: 2
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question: example.com
        resp.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        resp.extend_from_slice(&QTYPE_A.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());

        // Answer 1: A record (192.0.2.1)
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&QTYPE_A.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[192, 0, 2, 1]);

        // Answer 2: AAAA record (2001:db8::1)
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&16u16.to_be_bytes());
        let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        resp.extend_from_slice(&ipv6.octets());

        let a = DnsMessage::parse_a_record(&resp).unwrap();
        assert_eq!(a, Ipv4Addr::new(192, 0, 2, 1));

        let aaaa = DnsMessage::parse_aaaa_record(&resp).unwrap();
        assert_eq!(aaaa, ipv6);
    }
}
