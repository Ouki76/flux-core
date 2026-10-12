//! TUIC v5 protocol framing — spec-compliant (compatible with sing-box / mihomo).
//!
//! Frame layout (all frames start with `[VERSION=0x05, COMMAND]`):
//! - AUTHENTICATE (0x00): `[5, 0, uuid(16), token(32)]` on a dedicated
//!   unidirectional stream; token = TLS 1.3 ExportKeyingMaterial(label = raw UUID
//!   bytes, context = password) — provided by the QUIC layer, see `quinn::Connection`.
//! - CONNECT (0x01): `[5, 1, addr]` on a new bidirectional stream per TCP flow,
//!   followed by raw payload.
//! - PACKET (0x02): `[5, 2, session_id u16, packet_id u16, frag_total u8,
//!   frag_id u8, len u16, addr, payload]` over QUIC datagrams.
//! - DISSOCIATE (0x03): `[5, 3, session_id u16]` over a unidirectional stream.
//! - HEARTBEAT (0x04): `[5, 4]` over QUIC datagrams.
//!
//! Address encoding (TUIC-flavored, differs from SOCKS5 ATYP values):
//! `0x00` = domain (len u8 + bytes), `0x01` = IPv4, `0x02` = IPv6; port is last.

use flux_types::{FluxError, FluxResult, TargetAddress};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use uuid::Uuid;

pub const TUIC_VERSION: u8 = 5;
pub const TUIC_CMD_AUTHENTICATE: u8 = 0x00;
pub const TUIC_CMD_CONNECT: u8 = 0x01;
pub const TUIC_CMD_PACKET: u8 = 0x02;
pub const TUIC_CMD_DISSOCIATE: u8 = 0x03;
pub const TUIC_CMD_HEARTBEAT: u8 = 0x04;

pub const TUIC_AUTH_LEN: usize = 2 + 16 + 32;

const ATYP_DOMAIN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;
const ATYP_EMPTY: u8 = 0xff;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TuicV5Config {
    pub server: String,
    pub server_port: u16,
    pub uuid: Uuid,
    pub password: String,
    #[serde(default = "default_congestion")]
    pub congestion_control: String,
    #[serde(default = "default_zero_rtt")]
    pub zero_rtt: bool,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    /// ALPN protocols for the QUIC TLS handshake (default: ["tuic", "tuic-v5", "h3"]).
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

fn default_congestion() -> String {
    "bbr".into()
}
fn default_zero_rtt() -> bool {
    true
}

fn proto_err(msg: impl Into<String>) -> FluxError {
    FluxError::Protocol {
        protocol: "tuic5",
        message: msg.into(),
    }
}

pub struct TuicV5Protocol;

impl TuicV5Protocol {
    /// Builds an AUTHENTICATE frame. `token` is the 32-byte TLS 1.3
    /// ExportKeyingMaterial derived from the QUIC connection
    /// (label = raw UUID bytes, context = password).
    pub fn build_auth_frame(uuid: &Uuid, token: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TUIC_AUTH_LEN);
        buf.push(TUIC_VERSION);
        buf.push(TUIC_CMD_AUTHENTICATE);
        buf.extend_from_slice(uuid.as_bytes());
        buf.extend_from_slice(token);
        buf
    }

    /// Parses an AUTHENTICATE frame, returning (uuid, token). Token verification
    /// requires the QUIC connection and happens in the caller.
    pub fn parse_auth_frame(data: &[u8]) -> FluxResult<(Uuid, [u8; 32])> {
        if data.len() < TUIC_AUTH_LEN {
            return Err(proto_err("auth frame too short"));
        }
        if data[0] != TUIC_VERSION {
            return Err(proto_err(format!("unsupported tuic version {}", data[0])));
        }
        if data[1] != TUIC_CMD_AUTHENTICATE {
            return Err(proto_err(format!(
                "expected AUTHENTICATE command, got {}",
                data[1]
            )));
        }
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&data[2..18]);
        let mut token = [0u8; 32];
        token.copy_from_slice(&data[18..50]);
        Ok((Uuid::from_bytes(uuid_bytes), token))
    }

    /// Encodes a TUIC address (ATYP + addr + port, port last).
    pub fn encode_address(buf: &mut Vec<u8>, target: &TargetAddress) {
        match target {
            TargetAddress::Ip(SocketAddr::V4(v4)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            TargetAddress::Ip(SocketAddr::V6(v6)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
            TargetAddress::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Decodes a TUIC address, returning (address, bytes consumed).
    pub fn decode_address(data: &[u8]) -> FluxResult<(TargetAddress, usize)> {
        if data.is_empty() {
            return Err(proto_err("empty address"));
        }
        match data[0] {
            ATYP_IPV4 => {
                if data.len() < 1 + 4 + 2 {
                    return Err(proto_err("truncated ipv4 address"));
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((TargetAddress::Ip(SocketAddr::new(ip.into(), port)), 7))
            }
            ATYP_IPV6 => {
                if data.len() < 1 + 16 + 2 {
                    return Err(proto_err("truncated ipv6 address"));
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[1..17]);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((
                    TargetAddress::Ip(SocketAddr::new(Ipv6Addr::from(ip_bytes).into(), port)),
                    19,
                ))
            }
            ATYP_DOMAIN => {
                if data.len() < 2 {
                    return Err(proto_err("missing domain length"));
                }
                let len = data[1] as usize;
                if data.len() < 2 + len + 2 {
                    return Err(proto_err("truncated domain address"));
                }
                let domain = std::str::from_utf8(&data[2..2 + len])
                    .map_err(|e| proto_err(format!("invalid domain: {}", e)))?
                    .to_string();
                let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
                Ok((TargetAddress::Domain(domain, port), 2 + len + 2))
            }
            ATYP_EMPTY => Ok((
                TargetAddress::Ip(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)),
                1,
            )),
            other => Err(proto_err(format!("unknown address type {}", other))),
        }
    }

    /// Builds a CONNECT frame header (payload follows directly on the stream).
    pub fn build_connect_frame(target: &TargetAddress) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.push(TUIC_VERSION);
        buf.push(TUIC_CMD_CONNECT);
        Self::encode_address(&mut buf, target);
        buf
    }

    /// Builds a PACKET frame (UDP over QUIC datagram).
    pub fn build_packet_frame(
        session_id: u16,
        packet_id: u16,
        target: &TargetAddress,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10 + 16 + payload.len());
        buf.push(TUIC_VERSION);
        buf.push(TUIC_CMD_PACKET);
        buf.extend_from_slice(&session_id.to_be_bytes());
        buf.extend_from_slice(&packet_id.to_be_bytes());
        buf.push(1); // frag_total
        buf.push(0); // frag_id
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        Self::encode_address(&mut buf, target);
        buf.extend_from_slice(payload);
        buf
    }

    /// Parses a PACKET frame (single-fragment only; fragmented packets are rejected).
    pub fn parse_packet_frame(data: &[u8]) -> FluxResult<(u16, u16, TargetAddress, Vec<u8>)> {
        if data.len() < 10 {
            return Err(proto_err("packet frame too short"));
        }
        if data[0] != TUIC_VERSION || data[1] != TUIC_CMD_PACKET {
            return Err(proto_err("not a PACKET frame"));
        }
        let session_id = u16::from_be_bytes([data[2], data[3]]);
        let packet_id = u16::from_be_bytes([data[4], data[5]]);
        let frag_total = data[6];
        let frag_id = data[7];
        if frag_total > 1 || frag_id != 0 {
            return Err(proto_err("fragmented UDP packets are not supported"));
        }
        let len = u16::from_be_bytes([data[8], data[9]]) as usize;
        let (addr, addr_len) = Self::decode_address(&data[10..])?;
        let payload_start = 10 + addr_len;
        if data.len() < payload_start + len {
            return Err(proto_err("truncated packet payload"));
        }
        Ok((
            session_id,
            packet_id,
            addr,
            data[payload_start..payload_start + len].to_vec(),
        ))
    }

    /// Builds a DISSOCIATE frame (closes a UDP session).
    pub fn build_dissociate_frame(session_id: u16) -> Vec<u8> {
        vec![
            TUIC_VERSION,
            TUIC_CMD_DISSOCIATE,
            (session_id >> 8) as u8,
            session_id as u8,
        ]
    }

    /// Builds a HEARTBEAT datagram.
    pub fn build_heartbeat_frame() -> Vec<u8> {
        vec![TUIC_VERSION, TUIC_CMD_HEARTBEAT]
    }

    /// Legacy HMAC-SHA256 token for layered (non-QUIC) transports, where TLS
    /// ExportKeyingMaterial is unavailable. flux-extension only.
    pub fn legacy_token(uuid: &Uuid, password: &str) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(uuid.as_bytes());
        let res = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    /// Legacy combined command frame helpers (used by the TCP-pipeline layering).
    /// New code should use build_connect_frame / parse_connect_frame.
    pub fn build_command_frame(command: u8, target: &TargetAddress) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.push(TUIC_VERSION);
        buf.push(command);
        Self::encode_address(&mut buf, target);
        buf
    }

    /// Parses a command frame, returning (command, target).
    pub fn parse_command_frame(data: &[u8]) -> FluxResult<(u8, TargetAddress)> {
        if data.len() < 2 {
            return Err(proto_err("command frame too short"));
        }
        if data[0] != TUIC_VERSION {
            return Err(proto_err(format!("unsupported tuic version {}", data[0])));
        }
        let cmd = data[1];
        let (addr, _) = Self::decode_address(&data[2..])?;
        Ok((cmd, addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_frames_spec_layout() {
        let uuid = Uuid::new_v4();
        let token = [0xABu8; 32];

        let auth = TuicV5Protocol::build_auth_frame(&uuid, &token);
        assert_eq!(auth.len(), TUIC_AUTH_LEN);
        assert_eq!(auth[0], 5);
        assert_eq!(auth[1], TUIC_CMD_AUTHENTICATE);
        let (parsed_uuid, parsed_token) = TuicV5Protocol::parse_auth_frame(&auth).unwrap();
        assert_eq!(parsed_uuid, uuid);
        assert_eq!(parsed_token, token);

        let target = TargetAddress::domain("example.com", 443);
        let cmd = TuicV5Protocol::build_command_frame(TUIC_CMD_CONNECT, &target);
        assert_eq!(cmd[0], 5);
        assert_eq!(cmd[1], TUIC_CMD_CONNECT);
        assert_eq!(cmd[2], ATYP_DOMAIN);
        let (parsed_cmd, parsed_target) = TuicV5Protocol::parse_command_frame(&cmd).unwrap();
        assert_eq!(parsed_cmd, TUIC_CMD_CONNECT);
        assert_eq!(parsed_target, target);

        let pkt = TuicV5Protocol::build_packet_frame(7, 42, &target, b"udp-data");
        let (sid, pid, paddr, pdata) = TuicV5Protocol::parse_packet_frame(&pkt).unwrap();
        assert_eq!(sid, 7);
        assert_eq!(pid, 42);
        assert_eq!(paddr, target);
        assert_eq!(pdata, b"udp-data");

        // IPv4 roundtrip
        let v4: TargetAddress = "1.2.3.4:53".parse().unwrap();
        let f = TuicV5Protocol::build_connect_frame(&v4);
        assert_eq!(f[2], ATYP_IPV4);
        let (_, parsed_v4) = TuicV5Protocol::parse_command_frame(&f).unwrap();
        assert_eq!(parsed_v4, v4);

        // IPv6 roundtrip
        let v6: TargetAddress = "[2606:4700:4700::1111]:443".parse().unwrap();
        let f6 = TuicV5Protocol::build_connect_frame(&v6);
        assert_eq!(f6[2], ATYP_IPV6);
        let (_, parsed_v6) = TuicV5Protocol::parse_command_frame(&f6).unwrap();
        assert_eq!(parsed_v6, v6);
    }
}
