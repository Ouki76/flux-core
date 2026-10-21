//! DNS wire format (RFC 1035, RFC 3596, RFC 2308, RFC 6891, RFC 9460).
//!
//! The parser is a full section walker: it exposes questions, answers,
//! authority and additional records, models the record types a modern stub
//! resolver meets in practice (`A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `MX`, `SOA`,
//! `NS`, `HTTPS`/`SVCB`) and keeps anything else as opaque
//! [`RData::Unknown`] — an unmodelled type is never a parse failure.
//!
//! Everything is bounded:
//!
//! * a name has a 255-byte budget ([`MAX_NAME_LEN`]),
//! * a name may follow at most [`MAX_NAME_POINTER_HOPS`] compression pointers,
//!   and every pointer must target a *strictly earlier* offset, which makes a
//!   loop structurally impossible rather than merely unlikely,
//! * a section may hold at most [`MAX_SECTION_RECORDS`] records,
//! * every `rdlength` is range-checked before the payload is read.
//!
//! No input can make this module panic, spin, or allocate without bound. The
//! fuzz target (`fuzz/fuzz_targets/fuzz_dns_wire.rs`) and
//! `tests/test_dns_completeness.rs` both rely on that.

use flux_types::{FluxError, FluxResult};
use std::fmt;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Record type / class / rcode constants
// ---------------------------------------------------------------------------

pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_OPT: u16 = 41;
pub const QTYPE_SVCB: u16 = 64;
pub const QTYPE_HTTPS: u16 = 65;
pub const QTYPE_ANY: u16 = 255;

pub const QCLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// Maximum encoded length of a domain name (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum number of compression pointers followed while decoding one name.
pub const MAX_NAME_POINTER_HOPS: usize = 16;
/// Maximum number of records accepted in one section (question/answer/...).
pub const MAX_SECTION_RECORDS: usize = 1024;
/// Maximum number of CNAME hops followed inside one response.
pub const MAX_CNAME_CHAIN: usize = 16;
/// Maximum number of elements (TXT strings, SVCB params) kept per record.
const MAX_RDATA_ITEMS: usize = 64;

/// A DNS name, kept as its raw labels so it re-encodes losslessly.
///
/// Labels are byte strings, not `String`, because DNS labels are arbitrary
/// octets (RFC 1035 §3.1); the textual form escapes anything ambiguous.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// The root name (".").
    pub fn root() -> Self {
        Self::default()
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Encoded wire length, including the terminating root label.
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    /// Writes the uncompressed wire encoding.
    ///
    /// Names built by [`Name::from_str`] or decoded by the parser are always
    /// within [`MAX_NAME_LEN`]; the `debug_assert` keeps that visible.
    pub fn write_wire(&self, out: &mut Vec<u8>) {
        debug_assert!(self.wire_len() <= MAX_NAME_LEN);
        for label in &self.labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
    }

    /// Case-insensitive comparison (DNS names are case-insensitive, RFC 1035 §2.3.3).
    pub fn eq_ignore_ascii_case(&self, other: &Name) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(other.labels.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// True when `self` is `suffix` or a subdomain of it.
    pub fn is_subdomain_of(&self, suffix: &Name) -> bool {
        if self.labels.len() < suffix.labels.len() {
            return false;
        }
        let skip = self.labels.len() - suffix.labels.len();
        self.labels[skip..]
            .iter()
            .zip(suffix.labels.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// The name with its leftmost label removed, `None` for the root.
    pub fn parent(&self) -> Option<Name> {
        if self.labels.is_empty() {
            None
        } else {
            Some(Name {
                labels: self.labels[1..].to_vec(),
            })
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            for &b in label {
                match b {
                    b'.' | b'\\' => {
                        f.write_str("\\")?;
                        f.write_char(b as char)?;
                    }
                    0x21..=0x7e => f.write_char(b as char)?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

/// Parses the presentation form, honouring `\.`, `\\` and `\DDD`.
impl FromStr for Name {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if s.is_empty() || s == "." {
            return Ok(Name::root());
        }
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'.' => {
                    if current.is_empty() {
                        return Err(ParseError::BadName("empty label".into()));
                    }
                    labels.push(std::mem::take(&mut current));
                    i += 1;
                }
                b'\\' => {
                    let rest = &bytes[i + 1..];
                    if rest.len() >= 3 && rest[..3].iter().all(u8::is_ascii_digit) {
                        let v = (rest[0] - b'0') as u16 * 100
                            + (rest[1] - b'0') as u16 * 10
                            + (rest[2] - b'0') as u16;
                        if v > 255 {
                            return Err(ParseError::BadName("escape out of range".into()));
                        }
                        current.push(v as u8);
                        i += 4;
                    } else if let Some(&b) = rest.first() {
                        current.push(b);
                        i += 2;
                    } else {
                        return Err(ParseError::BadName("dangling escape".into()));
                    }
                }
                b => {
                    current.push(b);
                    i += 1;
                }
            }
            if current.len() > 63 {
                return Err(ParseError::BadName("label longer than 63 bytes".into()));
            }
        }
        if !current.is_empty() {
            labels.push(current);
        }
        let name = Name { labels };
        if name.wire_len() > MAX_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(name)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The packet ended in the middle of a field, name or rdata block.
    Truncated(&'static str),
    /// A label used one of the two reserved length encodings (0x40/0x80).
    ReservedLabelType(u8),
    /// The name was empty inside a label list, or an escape was invalid.
    BadName(String),
    NameTooLong,
    /// A compression pointer pointed forward or at itself.
    CompressionLoop,
    /// A compression pointer pointed outside the packet.
    BadPointer(usize),
    /// A section declared more records than [`MAX_SECTION_RECORDS`].
    TooManyRecords(&'static str),
    /// An rdata block did not match its declared length or type.
    BadRdata(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated(what) => write!(f, "malformed DNS packet: truncated {what}"),
            ParseError::ReservedLabelType(b) => {
                write!(f, "malformed DNS packet: reserved label type 0x{b:02x}")
            }
            ParseError::BadName(m) => write!(f, "malformed DNS name: {m}"),
            ParseError::NameTooLong => write!(f, "malformed DNS name: longer than 255 bytes"),
            ParseError::CompressionLoop => {
                write!(f, "malformed DNS packet: compression pointer loop")
            }
            ParseError::BadPointer(p) => {
                write!(
                    f,
                    "malformed DNS packet: compression pointer to {p} outside packet"
                )
            }
            ParseError::TooManyRecords(section) => {
                write!(f, "malformed DNS packet: too many {section} records")
            }
            ParseError::BadRdata(m) => write!(f, "malformed DNS rdata: {m}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for FluxError {
    fn from(e: ParseError) -> Self {
        FluxError::Dns(e.to_string())
    }
}

/// Why an upstream lookup produced no address.
///
/// The distinction is what makes caching correct: only [`QueryError::Negative`]
/// may be remembered as "this name does not resolve", and the SOA-derived TTL it
/// carries decides for how long.
#[derive(Debug)]
pub enum QueryError {
    /// A clean NXDOMAIN / NODATA answer. `ttl` is the negative TTL advertised by
    /// the response's SOA record, when there was one.
    Negative { ttl: Option<u32>, message: String },
    /// The response could not be understood (bad packet, CNAME loop, ...).
    Malformed(String),
    /// The server never answered / the connection failed. Never cached.
    Transport(FluxError),
}

impl QueryError {
    pub fn negative(message: impl Into<String>, ttl: Option<u32>) -> Self {
        QueryError::Negative {
            ttl,
            message: message.into(),
        }
    }

    pub fn malformed(message: impl Into<String>) -> Self {
        QueryError::Malformed(message.into())
    }

    /// Converts into the user-facing error, preserving transport variants so
    /// callers can tell a timeout from a "does not resolve".
    pub fn into_flux(self) -> FluxError {
        match self {
            QueryError::Negative { message, .. } | QueryError::Malformed(message) => {
                FluxError::Dns(message)
            }
            QueryError::Transport(e) => e,
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryError::Negative { message, .. } | QueryError::Malformed(message) => {
                f.write_str(message)
            }
            QueryError::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl From<QueryError> for FluxError {
    fn from(e: QueryError) -> Self {
        e.into_flux()
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// The decoded rdata of one resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Ptr(Name),
    /// SOA: primary NS, responsible mailbox, serial, refresh, retry, expire,
    /// minimum. `minimum` is the negative-caching TTL (RFC 2308 §5).
    Soa {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// One or more `<character-string>`s (RFC 1035 §3.3.14).
    Txt(Vec<Vec<u8>>),
    Mx {
        preference: u16,
        exchange: Name,
    },
    /// HTTPS/SVCB (RFC 9460): priority, target and the raw service parameters.
    Https {
        priority: u16,
        target: Name,
        params: Vec<(u16, Vec<u8>)>,
    },
    /// Any type this crate does not model; bytes preserved so callers can relay
    /// or inspect them instead of losing the record.
    Unknown(u16, Vec<u8>),
}

impl RData {
    /// The record type this rdata belongs to.
    pub fn rtype(&self) -> u16 {
        match self {
            RData::A(_) => QTYPE_A,
            RData::Aaaa(_) => QTYPE_AAAA,
            RData::Ns(_) => QTYPE_NS,
            RData::Cname(_) => QTYPE_CNAME,
            RData::Ptr(_) => QTYPE_PTR,
            RData::Soa { .. } => QTYPE_SOA,
            RData::Txt(_) => QTYPE_TXT,
            RData::Mx { .. } => QTYPE_MX,
            RData::Https { .. } => QTYPE_HTTPS,
            RData::Unknown(t, _) => *t,
        }
    }

    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            RData::A(v4) => Some(IpAddr::V4(*v4)),
            RData::Aaaa(v6) => Some(IpAddr::V6(*v6)),
            _ => None,
        }
    }

    /// Writes the uncompressed wire encoding of this rdata.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            RData::A(ip) => out.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.write_wire(out),
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.write_wire(out);
                rname.write_wire(out);
                for v in [serial, refresh, retry, expire, minimum] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            RData::Txt(strings) => {
                for s in strings {
                    let s = &s[..s.len().min(255)];
                    out.push(s.len() as u8);
                    out.extend_from_slice(s);
                }
            }
            RData::Mx {
                preference,
                exchange,
            } => {
                out.extend_from_slice(&preference.to_be_bytes());
                exchange.write_wire(out);
            }
            RData::Https {
                priority,
                target,
                params,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                target.write_wire(out);
                for (key, value) in params {
                    let value = &value[..value.len().min(u16::MAX as usize)];
                    out.extend_from_slice(&key.to_be_bytes());
                    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                    out.extend_from_slice(value);
                }
            }
            RData::Unknown(_, bytes) => out.extend_from_slice(bytes),
        }
    }
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

/// One question (entry of the question section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
}

/// The outcome of looking for an address of a given type in one response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// An address of the requested type. `ttl` is the minimum over the whole
    /// CNAME chain that led to it.
    Address { ip: IpAddr, ttl: u32 },
    /// The name is an alias and the response carried no address for it: the
    /// caller should re-query `target` (bounded by [`MAX_CNAME_CHAIN`]).
    Alias { target: Name, ttl: u32 },
    /// Clean negative: NXDOMAIN, or NOERROR with no record of the requested type.
    Negative { rcode: u8, ttl: Option<u32> },
    /// The response's CNAME chain loops or exceeds [`MAX_CNAME_CHAIN`].
    CnameLoop { chain: Vec<Name> },
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// Parses a complete message. Bounded and panic-free on any input.
    pub fn parse(data: &[u8]) -> Result<Message, ParseError> {
        let mut r = Reader::new(data);
        let id = r.u16()?;
        let flags = r.u16()?;
        let qdcount = r.u16()? as usize;
        let ancount = r.u16()? as usize;
        let nscount = r.u16()? as usize;
        let arcount = r.u16()? as usize;

        for (count, section) in [
            (qdcount, "question"),
            (ancount, "answer"),
            (nscount, "authority"),
            (arcount, "additional"),
        ] {
            if count > MAX_SECTION_RECORDS {
                return Err(ParseError::TooManyRecords(section));
            }
        }

        let mut questions = Vec::with_capacity(qdcount.min(4));
        for _ in 0..qdcount {
            // Compression is not valid in the question section (RFC 1035 §4.1.2).
            let (name, next) = read_name(data, r.pos, false)?;
            r.pos = next;
            let qtype = r.u16()?;
            let qclass = r.u16()?;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }

        let answers = Self::parse_section(&mut r, ancount)?;
        let authority = Self::parse_section(&mut r, nscount)?;
        let additional = Self::parse_section(&mut r, arcount)?;

        Ok(Message {
            id,
            flags,
            questions,
            answers,
            authority,
            additional,
        })
    }

    fn parse_section(r: &mut Reader<'_>, count: usize) -> Result<Vec<Record>, ParseError> {
        let mut out = Vec::with_capacity(count.min(16));
        for _ in 0..count {
            // A section cut short (truncated UDP datagram) yields the records
            // decoded so far instead of failing the packet; the caller decides
            // whether the partial data is enough (TC is checked separately).
            match Self::parse_record(r) {
                Ok(rec) => out.push(rec),
                // The datagram ended exactly at a record boundary (a truncated
                // response): keep what we decoded. A record that claims data
                // beyond the end while bytes remain is corruption, not EOF.
                Err(ParseError::Truncated(_)) if r.pos >= r.data.len() => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    fn parse_record(r: &mut Reader<'_>) -> Result<Record, ParseError> {
        let (name, next) = read_name(r.data, r.pos, true)?;
        r.pos = next;
        let rtype = r.u16()?;
        let rclass = r.u16()?;
        let ttl = r.u32()?;
        let rdlength = r.u16()? as usize;
        let rdata_start = r.pos;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or(ParseError::Truncated("rdata length"))?;
        if rdata_end > r.data.len() {
            return Err(ParseError::Truncated("rdata"));
        }

        // rdata names may use compression relative to the whole message, so the
        // sub-reader keeps the full packet but must not run past `rdata_end`.
        let mut sub = Reader::new(r.data);
        sub.pos = rdata_start;
        let rdata = match rtype {
            QTYPE_A => {
                if rdlength != 4 {
                    return Err(ParseError::BadRdata(format!(
                        "A record with rdlength {rdlength}"
                    )));
                }
                let b = sub.take(4)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            QTYPE_AAAA => {
                if rdlength != 16 {
                    return Err(ParseError::BadRdata(format!(
                        "AAAA record with rdlength {rdlength}"
                    )));
                }
                let b = sub.take(16)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(b);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            QTYPE_NS | QTYPE_CNAME | QTYPE_PTR => {
                let target = sub.name()?;
                if sub.pos > rdata_end {
                    return Err(ParseError::BadRdata("name overruns rdata".into()));
                }
                match rtype {
                    QTYPE_NS => RData::Ns(target),
                    QTYPE_CNAME => RData::Cname(target),
                    _ => RData::Ptr(target),
                }
            }
            QTYPE_SOA => {
                let mname = sub.name()?;
                let rname = sub.name()?;
                let serial = sub.u32()?;
                let refresh = sub.u32()?;
                let retry = sub.u32()?;
                let expire = sub.u32()?;
                let minimum = sub.u32()?;
                if sub.pos > rdata_end {
                    return Err(ParseError::BadRdata("SOA overruns rdata".into()));
                }
                RData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            QTYPE_MX => {
                let preference = sub.u16()?;
                let exchange = sub.name()?;
                if sub.pos > rdata_end {
                    return Err(ParseError::BadRdata("MX overruns rdata".into()));
                }
                RData::Mx {
                    preference,
                    exchange,
                }
            }
            QTYPE_TXT => {
                let mut strings = Vec::new();
                while sub.pos < rdata_end && strings.len() < MAX_RDATA_ITEMS {
                    let len = sub.u8()? as usize;
                    if len == 0 {
                        // Zero-length character-strings are legal; keep them.
                        strings.push(Vec::new());
                        continue;
                    }
                    let s = sub.take(len)?;
                    if sub.pos > rdata_end {
                        return Err(ParseError::BadRdata("TXT string overruns rdata".into()));
                    }
                    strings.push(s.to_vec());
                }
                RData::Txt(strings)
            }
            QTYPE_SVCB | QTYPE_HTTPS => {
                let priority = sub.u16()?;
                let target = sub.name()?;
                let mut params = Vec::new();
                while sub.pos + 4 <= rdata_end && params.len() < MAX_RDATA_ITEMS {
                    let key = sub.u16()?;
                    let len = sub.u16()? as usize;
                    let value = sub.take(len)?.to_vec();
                    if sub.pos > rdata_end {
                        return Err(ParseError::BadRdata("SVCB param overruns rdata".into()));
                    }
                    params.push((key, value));
                }
                RData::Https {
                    priority,
                    target,
                    params,
                }
            }
            other => RData::Unknown(other, r.data[rdata_start..rdata_end].to_vec()),
        };

        r.pos = rdata_end;
        Ok(Record {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        })
    }

    /// Finds an address of `qtype` for `qname`, following CNAMEs.
    ///
    /// The chain is followed inside the answer section (which is how recursive
    /// resolvers return it) and is bounded by [`MAX_CNAME_CHAIN`]; a loop is
    /// reported as [`Answer::CnameLoop`] instead of spinning.
    pub fn answer(&self, qname: &Name, qtype: u16) -> Answer {
        let rcode = self.rcode();
        if rcode != RCODE_NOERROR {
            return Answer::Negative {
                rcode,
                ttl: self.negative_ttl(),
            };
        }

        let mut current = qname.clone();
        let mut chain: Vec<Name> = vec![qname.clone()];
        let mut chain_ttl: Option<u32> = None;

        for _ in 0..MAX_CNAME_CHAIN {
            let rrset: Vec<&Record> = self
                .answers
                .iter()
                .filter(|r| r.rtype == qtype && r.name.eq_ignore_ascii_case(&current))
                .collect();
            if let Some(ip) = rrset.iter().find_map(|r| r.rdata.as_ip()) {
                // RFC 2181 §5.2 says an RRset shares one TTL; use the smallest so
                // the cache can never outlive any record of the set.
                let rrset_ttl = rrset.iter().map(|r| r.ttl).min().unwrap_or(0);
                let ttl = chain_ttl.map_or(rrset_ttl, |c| c.min(rrset_ttl));
                return Answer::Address { ip, ttl };
            }

            let Some(cname) = self
                .answers
                .iter()
                .find(|r| r.rtype == QTYPE_CNAME && r.name.eq_ignore_ascii_case(&current))
            else {
                break;
            };
            let RData::Cname(target) = &cname.rdata else {
                break;
            };
            chain_ttl = Some(chain_ttl.map_or(cname.ttl, |c| c.min(cname.ttl)));
            let loops = chain.iter().any(|n| n.eq_ignore_ascii_case(target));
            chain.push(target.clone());
            if loops {
                return Answer::CnameLoop { chain };
            }
            current = target.clone();
        }

        if current != *qname {
            if chain.len() > MAX_CNAME_CHAIN {
                return Answer::CnameLoop { chain };
            }
            return Answer::Alias {
                target: current,
                ttl: chain_ttl.unwrap_or(0),
            };
        }

        Answer::Negative {
            rcode,
            ttl: self.negative_ttl(),
        }
    }

    /// Negative-caching TTL from the SOA record (RFC 2308 §5): the SOA `MINIMUM`
    /// field capped by the SOA record's own TTL.
    pub fn negative_ttl(&self) -> Option<u32> {
        self.authority
            .iter()
            .chain(self.answers.iter())
            .find_map(|r| match &r.rdata {
                RData::Soa { minimum, .. } => Some((*minimum).min(r.ttl)),
                _ => None,
            })
    }

    /// First address record of any family, ignoring owner names. Used by the
    /// legacy single-record helpers (and by the fuzz target).
    pub fn first_address(&self) -> Option<(IpAddr, u32)> {
        self.answers
            .iter()
            .find_map(|r| r.rdata.as_ip().map(|ip| (ip, r.ttl)))
    }

    /// First address record of `qtype`, ignoring owner names.
    pub fn first_address_of(&self, qtype: u16) -> Option<(IpAddr, u32)> {
        self.answers
            .iter()
            .filter(|r| r.rtype == qtype)
            .find_map(|r| r.rdata.as_ip().map(|ip| (ip, r.ttl)))
    }
}

// ---------------------------------------------------------------------------
// Bounded reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ParseError::Truncated("length overflow"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(ParseError::Truncated("field"))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn name(&mut self) -> Result<Name, ParseError> {
        let (name, next) = read_name(self.data, self.pos, true)?;
        self.pos = next;
        Ok(name)
    }
}

/// Decodes one (possibly compressed) name starting at `start`.
///
/// Returns the name and the offset just past it *in the original position*
/// (i.e. past the first pointer, if any). Every pointer must target a strictly
/// smaller offset, so the walk always makes progress; the explicit hop budget
/// is a second, independent bound.
fn read_name(
    data: &[u8],
    start: usize,
    allow_compression: bool,
) -> Result<(Name, usize), ParseError> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut hops = 0usize;
    let mut total = 1usize; // terminating root label

    loop {
        let b = *data.get(pos).ok_or(ParseError::Truncated("name"))?;
        match b & 0xC0 {
            0x00 if b == 0 => {
                end.get_or_insert(pos + 1);
                break;
            }
            0x00 => {
                let len = b as usize;
                let label = data
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(ParseError::Truncated("label"))?;
                total += len + 1;
                if total > MAX_NAME_LEN {
                    return Err(ParseError::NameTooLong);
                }
                if labels.len() >= 128 {
                    return Err(ParseError::NameTooLong);
                }
                labels.push(label.to_vec());
                pos += 1 + len;
            }
            0xC0 if allow_compression => {
                let lo = *data.get(pos + 1).ok_or(ParseError::Truncated("pointer"))?;
                let target = ((b as usize & 0x3F) << 8) | lo as usize;
                end.get_or_insert(pos + 2);
                // Backwards-only pointers: the offset strictly decreases on every
                // jump, so a loop cannot happen. This also rejects the classic
                // "pointer to itself" and "two pointers pointing at each other".
                if target >= pos {
                    return Err(ParseError::CompressionLoop);
                }
                if target >= data.len() {
                    return Err(ParseError::BadPointer(target));
                }
                hops += 1;
                if hops > MAX_NAME_POINTER_HOPS {
                    return Err(ParseError::CompressionLoop);
                }
                pos = target;
            }
            _ => return Err(ParseError::ReservedLabelType(b)),
        }
    }

    Ok((Name { labels }, end.unwrap_or(pos + 1)))
}

// ---------------------------------------------------------------------------
// Builder / convenience API
// ---------------------------------------------------------------------------

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
        // Unrepresentable names are rejected by `is_valid_domain` before reaching
        // here; fall back to the root so a malformed name can never silently be
        // turned into a *different* question.
        let name = Name::from_str(domain).unwrap_or_else(|_| Name::root());
        Self::build_query_for_name(&name, qtype, client_subnet, tx_id)
    }

    /// Builds a query for an already-parsed [`Name`] (used when following CNAMEs).
    pub fn build_query_for_name(
        name: &Name,
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
        buf.extend_from_slice(&(if has_ecs { 1u16 } else { 0u16 }).to_be_bytes()); // ARCOUNT

        name.write_wire(&mut buf);

        // QTYPE and QCLASS (IN = 1)
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());

        // Optional EDNS0 RR (RFC 7871 Client Subnet)
        if let Some(subnet) = client_subnet {
            buf.push(0x00); // Root domain name
            buf.extend_from_slice(&QTYPE_OPT.to_be_bytes()); // TYPE = OPT (41)
            buf.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
            buf.extend_from_slice(&0u32.to_be_bytes()); // TTL = extended RCODE + flags

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

            buf.extend_from_slice(&8u16.to_be_bytes()); // Option Code 8 = Client Subnet
            buf.extend_from_slice(&(option_len as u16).to_be_bytes());
            buf.extend_from_slice(&family.to_be_bytes());
            buf.push(prefix_len);
            buf.push(0x00); // Scope prefix length = 0 in query
            buf.extend_from_slice(&addr_bytes);
        }

        buf
    }

    /// True when `domain` is a syntactically valid DNS name: 1..=255 bytes, no
    /// empty labels, every label 1..=63 bytes.
    pub fn is_valid_domain(domain: &str) -> bool {
        if domain.is_empty() || domain.len() > 255 {
            return false;
        }
        let trimmed = domain.strip_suffix('.').unwrap_or(domain);
        if trimmed.is_empty() {
            return true; // the root
        }
        trimmed.split('.').all(|l| !l.is_empty() && l.len() <= 63)
    }

    /// Parses the question section of a DNS query.
    ///
    /// Returns `(transaction_id, flags, qname, qtype, question_end_offset)`.
    /// `None` when the packet is too short or the name is malformed.
    pub fn parse_question(data: &[u8]) -> Option<(u16, u16, String, u16, usize)> {
        let (tx_id, flags, name, qtype, end) = Self::parse_question_name(data)?;
        Some((tx_id, flags, name.to_string(), qtype, end))
    }

    /// Like [`Self::parse_question`] but returns the structured [`Name`].
    pub fn parse_question_name(data: &[u8]) -> Option<(u16, u16, Name, u16, usize)> {
        if data.len() < 12 {
            return None;
        }
        let tx_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if qdcount == 0 {
            return None;
        }
        // No compression in a question: a 0xC0 prefix would otherwise be read as
        // a 192-byte label.
        let (name, pos) = read_name(data, 12, false).ok()?;
        if pos + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let end = pos + 4; // qtype + qclass
        Some((tx_id, flags, name, qtype, end))
    }

    /// Builds a DNS response for `query`.
    ///
    /// The ID and question are echoed verbatim; `answer` (when `Some`) is appended
    /// as a single A record with a 1-second TTL, which is what a fake-IP resolver
    /// wants (the mapping must be short-lived). When `answer` is `None` the
    /// response carries no records (NODATA) so clients fail over quickly.
    pub fn build_response(query: &[u8], answer: Option<Ipv4Addr>) -> Option<Vec<u8>> {
        Self::build_response_ip(query, answer.map(IpAddr::V4))
    }

    /// Like [`Self::build_response`] but for either family: the record type
    /// follows the address family.
    pub fn build_response_ip(query: &[u8], answer: Option<IpAddr>) -> Option<Vec<u8>> {
        let answers: Vec<(RData, u32)> = match answer {
            Some(IpAddr::V4(v4)) => vec![(RData::A(v4), 1)],
            Some(IpAddr::V6(v6)) => vec![(RData::Aaaa(v6), 1)],
            None => Vec::new(),
        };
        Self::build_response_records(query, RCODE_NOERROR, &answers)
    }

    /// Builds a response carrying one PTR record pointing at `target` (used to
    /// reverse-map fake addresses back to their domain).
    pub fn build_response_ptr(query: &[u8], target: &Name) -> Option<Vec<u8>> {
        Self::build_response_records(query, RCODE_NOERROR, &[(RData::Ptr(target.clone()), 1)])
    }

    /// Builds a response with an arbitrary answer set and rcode.
    ///
    /// Answer names are encoded as a pointer to the question name, which is
    /// correct here because every record we synthesise is owned by the queried
    /// name.
    pub fn build_response_records(
        query: &[u8],
        rcode: u8,
        answers: &[(RData, u32)],
    ) -> Option<Vec<u8>> {
        let (tx_id, flags, _qname, _qtype, q_end) = Self::parse_question(query)?;
        let mut out = Vec::with_capacity(q_end + 32 * answers.len().max(1));
        out.extend_from_slice(&tx_id.to_be_bytes());
        // QR=1, copy RD from the query, RA=1, RCODE as requested.
        let resp_flags = 0x8000u16 | (flags & 0x0100) | 0x0080 | u16::from(rcode & 0x000F);
        out.extend_from_slice(&resp_flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&(answers.len().min(u16::MAX as usize) as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        out.extend_from_slice(&query[12..q_end]);
        for (rdata, ttl) in answers {
            out.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
            out.extend_from_slice(&rdata.rtype().to_be_bytes());
            out.extend_from_slice(&QCLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            let mut body = Vec::with_capacity(32);
            rdata.encode(&mut body);
            out.extend_from_slice(&(body.len().min(u16::MAX as usize) as u16).to_be_bytes());
            out.extend_from_slice(&body);
        }
        Some(out)
    }

    /// Validates a DNS response header:
    /// - length >= 12
    /// - matching transaction ID
    /// - QR flag is 1 (response)
    /// - RCODE is 0 (NoError)
    pub fn validate_response(data: &[u8], expected_tx_id: u16) -> FluxResult<()> {
        Self::validate_response_header(data, expected_tx_id)?;
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(FluxError::Dns(format!(
                "DNS query returned error RCODE {}",
                rcode
            )));
        }
        Ok(())
    }

    /// Header sanity check that deliberately accepts an error RCODE.
    ///
    /// Transports use this so that NXDOMAIN/NODATA reach the parser, which turns
    /// them into a cacheable negative with the SOA-derived TTL instead of a
    /// generic transport failure.
    pub fn validate_response_header(data: &[u8], expected_tx_id: u16) -> FluxResult<()> {
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
        if (flags & 0x8000) == 0 {
            return Err(FluxError::Dns("DNS packet is not a response (QR=0)".into()));
        }
        Ok(())
    }

    /// Parses a response and returns the answer for `qtype`, following CNAMEs
    /// inside the packet.
    ///
    /// This is the entry point every transport (UDP, DoH, DoT, DoQ) uses, so the
    /// caching rules downstream see one consistent classification: a clean
    /// negative is distinguishable from a broken or truncated packet.
    pub fn parse_response(data: &[u8], qname: &Name, qtype: u16) -> Result<Answer, QueryError> {
        let msg = Message::parse(data)
            .map_err(|e| QueryError::Malformed(format!("unparseable DNS response: {e}")))?;
        let answer = msg.answer(qname, qtype);
        // A truncated answer is incomplete, not a negative: retrying over TCP (or
        // against another server) is the right response, and it must not be
        // remembered as "this name does not resolve".
        if !matches!(answer, Answer::Address { .. }) && msg.is_truncated() {
            return Err(QueryError::malformed(format!(
                "truncated DNS response for {qname}"
            )));
        }
        Ok(answer)
    }

    /// Parses a response and returns the address for `qtype`, or a clean
    /// [`QueryError`] explaining why there is none.
    pub fn parse_answer(
        data: &[u8],
        qname: &Name,
        qtype: u16,
    ) -> Result<(IpAddr, u32), QueryError> {
        match Self::parse_response(data, qname, qtype)? {
            Answer::Address { ip, ttl } => {
                if ip.is_ipv4() == (qtype == QTYPE_A) {
                    Ok((ip, ttl))
                } else {
                    Err(QueryError::malformed(format!(
                        "DNS response held an address of the wrong family for a type {qtype} query"
                    )))
                }
            }
            Answer::Alias { target, .. } => Err(QueryError::malformed(format!(
                "DNS response for {qname} ended in a CNAME to {target} without the requested record"
            ))),
            Answer::Negative { rcode, ttl } => Err(QueryError::negative(
                format!(
                    "'{qname}' has no record of type {qtype} (rcode {rcode}{})",
                    match ttl {
                        Some(t) => format!(", negative TTL {t}s"),
                        None => String::new(),
                    }
                ),
                ttl,
            )),
            Answer::CnameLoop { chain } => Err(QueryError::malformed(format!(
                "CNAME loop while resolving {qname}: {}",
                chain
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ))),
        }
    }

    /// Legacy helper: first A (preferred) or AAAA address in the response.
    pub fn parse_ip_record_with_ttl(data: &[u8]) -> FluxResult<(IpAddr, u32)> {
        let msg = Message::parse(data)?;
        if let Some(v4) = msg.first_address_of(QTYPE_A) {
            return Ok(v4);
        }
        if let Some(v6) = msg.first_address_of(QTYPE_AAAA) {
            return Ok(v6);
        }
        Err(FluxError::Dns(
            "no valid A or AAAA record found in DNS response".into(),
        ))
    }

    /// Legacy helper: first A (preferred) or AAAA address in the response.
    pub fn parse_ip_record(data: &[u8]) -> FluxResult<IpAddr> {
        Self::parse_ip_record_with_ttl(data).map(|(ip, _)| ip)
    }

    /// Parses the first A (IPv4) record from a DNS response in wireformat.
    pub fn parse_a_record(data: &[u8]) -> FluxResult<Ipv4Addr> {
        let msg = Message::parse(data)?;
        match msg.first_address_of(QTYPE_A) {
            Some((IpAddr::V4(v4), _)) => Ok(v4),
            Some((IpAddr::V6(_), _)) => Err(FluxError::Dns("expected A record, got AAAA".into())),
            None => Err(FluxError::Dns(
                "no valid A record found in DNS response".into(),
            )),
        }
    }

    /// Parses the first AAAA (IPv6) record from a DNS response in wireformat.
    pub fn parse_aaaa_record(data: &[u8]) -> FluxResult<Ipv6Addr> {
        let msg = Message::parse(data)?;
        match msg.first_address_of(QTYPE_AAAA) {
            Some((IpAddr::V6(v6), _)) => Ok(v6),
            Some((IpAddr::V4(_), _)) => Err(FluxError::Dns("expected AAAA record, got A".into())),
            None => Err(FluxError::Dns(
                "no valid AAAA record found in DNS response".into(),
            )),
        }
    }

    /// Parses the first record of `target_qtype` in a response, following CNAMEs
    /// starting at the response's own question name.
    pub fn parse_specific_record_with_ttl(
        data: &[u8],
        target_qtype: u16,
    ) -> FluxResult<(IpAddr, u32)> {
        let msg = Message::parse(data)?;
        if let Some(q) = msg.questions.first()
            && let Answer::Address { ip, ttl } = msg.answer(&q.name, target_qtype)
        {
            return Ok((ip, ttl));
        }
        if let Some(rec) = msg.first_address_of(target_qtype) {
            return Ok(rec);
        }
        Err(FluxError::Dns(format!(
            "no matching record with type {} found in DNS response",
            target_qtype
        )))
    }
}

// ---------------------------------------------------------------------------
// Reverse (PTR) name helpers
// ---------------------------------------------------------------------------

/// Builds the `in-addr.arpa` / `ip6.arpa` name for an address.
pub fn ip_to_ptr_name(ip: &IpAddr) -> Name {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    match ip {
        IpAddr::V4(v4) => {
            for octet in v4.octets().iter().rev() {
                labels.push(octet.to_string().into_bytes());
            }
            labels.push(b"in-addr".to_vec());
            labels.push(b"arpa".to_vec());
        }
        IpAddr::V6(v6) => {
            // 32 reversed nibbles (RFC 3596 §2.5).
            for byte in v6.octets().iter().rev() {
                labels.push(vec![hex_nibble(byte & 0x0F)]);
                labels.push(vec![hex_nibble(byte >> 4)]);
            }
            labels.push(b"ip6".to_vec());
            labels.push(b"arpa".to_vec());
        }
    }
    Name { labels }
}

fn hex_nibble(v: u8) -> u8 {
    match v {
        0..=9 => b'0' + v,
        _ => b'a' + (v - 10),
    }
}

/// Parses an `in-addr.arpa` / `ip6.arpa` name back into an address.
pub fn ptr_name_to_ip(name: &Name) -> Option<IpAddr> {
    let lower: Vec<String> = name
        .labels()
        .iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect();

    if lower.len() == 6 && lower[4] == "in-addr" && lower[5] == "arpa" {
        let mut octets = [0u8; 4];
        for (i, slot) in octets.iter_mut().enumerate() {
            *slot = lower[3 - i].parse::<u8>().ok()?;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }

    if lower.len() == 34 && lower[32] == "ip6" && lower[33] == "arpa" {
        let mut octets = [0u8; 16];
        for (i, byte) in octets.iter_mut().rev().enumerate() {
            let lo = u8::from_str_radix(&lower[2 * i], 16).ok()?;
            let hi = u8::from_str_radix(&lower[2 * i + 1], 16).ok()?;
            *byte = (hi << 4) | lo;
        }
        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }

    None
}

// ---------------------------------------------------------------------------
// Tests: hand-built packets only (no network)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod packet_builder {
    //! Byte-by-byte packet construction helpers for the unit tests.

    /// Standard flags for a NOERROR response that echoes RD.
    pub const RESP_FLAGS: u16 = 0x8180;

    /// Encodes a dotted name as uncompressed wire labels.
    pub fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if name.is_empty() || name == "." {
            out.push(0);
            return out;
        }
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    pub struct Packet {
        pub buf: Vec<u8>,
        pub ancount: u16,
        pub nscount: u16,
    }

    impl Packet {
        pub fn new(id: u16, flags: u16) -> Self {
            let mut buf = Vec::new();
            buf.extend_from_slice(&id.to_be_bytes());
            buf.extend_from_slice(&flags.to_be_bytes());
            buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
            buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT (patched on finish)
            buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT (patched on finish)
            buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
            Self {
                buf,
                ancount: 0,
                nscount: 0,
            }
        }

        pub fn name(&mut self, name: &str) -> &mut Self {
            self.buf.extend_from_slice(&encode_name(name));
            self
        }

        pub fn question(&mut self, name: &str, qtype: u16) -> &mut Self {
            self.name(name);
            self.buf.extend_from_slice(&qtype.to_be_bytes());
            self.buf.extend_from_slice(&1u16.to_be_bytes());
            self
        }

        /// Starts a record owned by a compression pointer to `offset`.
        pub fn ptr_owner(&mut self, offset: u16) -> &mut Self {
            self.buf
                .extend_from_slice(&[0xC0 | (offset >> 8) as u8, offset as u8]);
            self
        }

        /// Appends one record with explicit rdata bytes.
        pub fn record(&mut self, rtype: u16, ttl: u32, rdata: &[u8]) -> &mut Self {
            self.buf.extend_from_slice(&rtype.to_be_bytes());
            self.buf.extend_from_slice(&1u16.to_be_bytes()); // IN
            self.buf.extend_from_slice(&ttl.to_be_bytes());
            self.buf
                .extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            self.buf.extend_from_slice(rdata);
            self
        }

        pub fn answer(&mut self) -> &mut Self {
            self.ancount += 1;
            self
        }

        pub fn authority(&mut self) -> &mut Self {
            self.nscount += 1;
            self
        }

        pub fn finish(&mut self) -> Vec<u8> {
            let mut out = self.buf.clone();
            out[6..8].copy_from_slice(&self.ancount.to_be_bytes());
            out[8..10].copy_from_slice(&self.nscount.to_be_bytes());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::packet_builder::{Packet, RESP_FLAGS, encode_name};
    use super::*;

    fn parse_ok(bytes: &[u8]) -> Message {
        Message::parse(bytes).expect("packet must parse")
    }

    // -- names ------------------------------------------------------------

    #[test]
    fn name_roundtrip_and_escaping() {
        let n: Name = "A.example.COM".parse().unwrap();
        assert_eq!(n.to_string(), "A.example.COM");
        assert!(n.eq_ignore_ascii_case(&"a.example.com".parse().unwrap()));
        assert!(n.is_subdomain_of(&"example.com".parse().unwrap()));
        assert!(!n.is_subdomain_of(&"other.com".parse().unwrap()));

        // A label containing a dot survives a textual round-trip.
        let weird: Name = r"a\.b.example".parse().unwrap();
        assert_eq!(weird.labels().len(), 2);
        assert_eq!(weird.labels()[0], b"a.b");
        assert_eq!(weird.to_string(), r"a\.b.example");

        assert!(".".parse::<Name>().unwrap().is_root());
        assert_eq!(Name::root().to_string(), ".");
        assert_eq!(Name::root().wire_len(), 1);
        assert_eq!("a.b".parse::<Name>().unwrap().wire_len(), 5);
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert!("a..b".parse::<Name>().is_err());
        let long_label = "a".repeat(64);
        assert!(format!("{long_label}.com").parse::<Name>().is_err());
        let long_name = vec!["a".repeat(63); 5].join(".");
        assert!(long_name.parse::<Name>().is_err());
    }

    #[test]
    fn compressed_names_are_expanded() {
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("www.example.com", QTYPE_A);
        p.ptr_owner(12).record(QTYPE_CNAME, 60, &[0xC0, 0x0C]);
        p.answer();
        let msg = parse_ok(&p.finish());
        assert_eq!(msg.answers[0].name.to_string(), "www.example.com");
        assert_eq!(
            msg.answers[0].rdata,
            RData::Cname("www.example.com".parse().unwrap())
        );
    }

    // -- CNAME chains -----------------------------------------------------

    #[test]
    fn cname_chain_yields_last_address_and_min_ttl() {
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("www.example.com", QTYPE_A);

        p.ptr_owner(12)
            .record(QTYPE_CNAME, 300, &encode_name("edge.example.com"));
        p.answer();
        p.name("edge.example.com")
            .record(QTYPE_CNAME, 120, &encode_name("origin.example.com"));
        p.answer();
        p.name("origin.example.com")
            .record(QTYPE_A, 60, &[203, 0, 113, 7]);
        p.answer();

        let msg = parse_ok(&p.finish());
        let qname: Name = "www.example.com".parse().unwrap();
        assert_eq!(
            msg.answer(&qname, QTYPE_A),
            Answer::Address {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                ttl: 60,
            },
            "must be the address of the canonical name with the chain's minimum TTL"
        );
    }

    #[test]
    fn cname_chain_is_found_through_out_of_order_records() {
        // The A record arrives before the CNAME that points at it (legal).
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("www.example.com", QTYPE_A);
        p.name("edge.example.com")
            .record(QTYPE_A, 45, &[203, 0, 113, 9]);
        p.answer();
        p.ptr_owner(12)
            .record(QTYPE_CNAME, 300, &encode_name("edge.example.com"));
        p.answer();

        let msg = parse_ok(&p.finish());
        let qname: Name = "www.example.com".parse().unwrap();
        assert_eq!(
            msg.answer(&qname, QTYPE_A),
            Answer::Address {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                ttl: 45,
            }
        );
    }

    #[test]
    fn cname_only_response_reports_alias_target() {
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("www.example.com", QTYPE_A);
        p.ptr_owner(12)
            .record(QTYPE_CNAME, 300, &encode_name("edge.example.com"));
        p.answer();

        let bytes = p.finish();
        let msg = parse_ok(&bytes);
        let qname: Name = "www.example.com".parse().unwrap();
        assert_eq!(
            msg.answer(&qname, QTYPE_A),
            Answer::Alias {
                target: "edge.example.com".parse().unwrap(),
                ttl: 300,
            }
        );
        // The transport-level helper reports "no usable answer", not a bogus IP.
        assert!(matches!(
            DnsMessage::parse_answer(&bytes, &qname, QTYPE_A),
            Err(QueryError::Malformed(_))
        ));
        // ... and the legacy helper falls back to "not found".
        assert!(DnsMessage::parse_specific_record_with_ttl(&bytes, QTYPE_A).is_err());
    }

    #[test]
    fn cname_loop_inside_one_message_is_detected() {
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("a.test", QTYPE_A);
        p.ptr_owner(12)
            .record(QTYPE_CNAME, 10, &encode_name("b.test"));
        p.answer();
        p.name("b.test")
            .record(QTYPE_CNAME, 10, &encode_name("a.test"));
        p.answer();

        let msg = parse_ok(&p.finish());
        let qname: Name = "a.test".parse().unwrap();
        match msg.answer(&qname, QTYPE_A) {
            Answer::CnameLoop { chain } => {
                assert_eq!(chain.len(), 3, "a.test -> b.test -> a.test");
            }
            other => panic!("loop must be detected, got {other:?}"),
        }
    }

    #[test]
    fn cname_chain_depth_is_bounded() {
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("n0.test", QTYPE_A);
        for i in 0..(MAX_CNAME_CHAIN + 5) {
            p.name(&format!("n{i}.test")).record(
                QTYPE_CNAME,
                10,
                &encode_name(&format!("n{}.test", i + 1)),
            );
            p.answer();
        }
        let msg = parse_ok(&p.finish());
        let qname: Name = "n0.test".parse().unwrap();
        assert!(
            matches!(msg.answer(&qname, QTYPE_A), Answer::CnameLoop { .. }),
            "an over-long chain must be reported, not followed forever"
        );
    }

    // -- record breadth ---------------------------------------------------

    #[test]
    fn parses_ptr_txt_mx_and_https() {
        let mut p = Packet::new(0x2222, RESP_FLAGS);
        p.question("example.com", QTYPE_HTTPS);

        p.ptr_owner(12)
            .record(QTYPE_PTR, 30, &encode_name("host.example.com"));
        p.answer();

        // TXT "v=spf1 -all" split into two character-strings.
        let mut txt = vec![10u8];
        txt.extend_from_slice(b"v=spf1 -al");
        txt.push(1);
        txt.extend_from_slice(b"l");
        p.ptr_owner(12).record(QTYPE_TXT, 30, &txt);
        p.answer();

        // MX 10 mail.example.com
        let mut mx = vec![0u8, 10];
        mx.extend_from_slice(&encode_name("mail.example.com"));
        p.ptr_owner(12).record(QTYPE_MX, 30, &mx);
        p.answer();

        // HTTPS priority 1, target ".", one `alpn` parameter.
        let mut https = vec![0u8, 1, 0];
        https.extend_from_slice(&[0u8, 1]); // key = alpn
        https.extend_from_slice(&6u16.to_be_bytes()); // value length
        https.extend_from_slice(&[2, b'h', b'2', 2, b'h', b'3']);
        p.ptr_owner(12).record(QTYPE_HTTPS, 30, &https);
        p.answer();

        let msg = parse_ok(&p.finish());
        assert_eq!(msg.answers.len(), 4, "no record may be dropped");

        assert_eq!(
            msg.answers[0].rdata,
            RData::Ptr("host.example.com".parse().unwrap())
        );
        assert_eq!(
            msg.answers[1].rdata,
            RData::Txt(vec![b"v=spf1 -al".to_vec(), b"l".to_vec()])
        );
        assert_eq!(
            msg.answers[2].rdata,
            RData::Mx {
                preference: 10,
                exchange: "mail.example.com".parse().unwrap()
            }
        );
        match &msg.answers[3].rdata {
            RData::Https {
                priority,
                target,
                params,
            } => {
                assert_eq!(*priority, 1);
                assert!(target.is_root());
                assert_eq!(params.len(), 1);
                assert_eq!(params[0], (1, vec![2, b'h', b'2', 2, b'h', b'3']));
            }
            other => panic!("expected HTTPS record, got {other:?}"),
        }
        // Round-trip: the same rdata re-encodes and parses back identically.
        let mut body = Vec::new();
        msg.answers[3].rdata.encode(&mut body);
        assert_eq!(body, https[..]);
    }

    #[test]
    fn unknown_record_types_are_kept_not_rejected() {
        let mut p = Packet::new(0x3333, RESP_FLAGS);
        p.question("example.com", QTYPE_A);
        p.ptr_owner(12).record(99, 30, &[1, 2, 3, 4]);
        p.answer();
        p.ptr_owner(12).record(QTYPE_A, 30, &[192, 0, 2, 9]);
        p.answer();

        let bytes = p.finish();
        let msg = parse_ok(&bytes);
        assert_eq!(msg.answers.len(), 2);
        assert_eq!(msg.answers[0].rdata, RData::Unknown(99, vec![1, 2, 3, 4]));
        assert_eq!(msg.answers[0].rtype, 99);
        assert_eq!(
            DnsMessage::parse_a_record(&bytes).unwrap(),
            Ipv4Addr::new(192, 0, 2, 9)
        );
    }

    #[test]
    fn nodata_with_unknown_qtype_is_not_a_parse_failure() {
        let mut p = Packet::new(0x4444, RESP_FLAGS);
        p.question("example.com", QTYPE_ANY);
        let bytes = p.finish();
        let msg = parse_ok(&bytes);
        assert!(msg.answers.is_empty());
        assert_eq!(msg.rcode(), RCODE_NOERROR);
        let qname: Name = "example.com".parse().unwrap();
        assert!(matches!(
            DnsMessage::parse_answer(&bytes, &qname, QTYPE_A),
            Err(QueryError::Negative { ttl: None, .. })
        ));
    }

    #[test]
    fn truncated_responses_are_not_cached_as_negative() {
        let mut p = Packet::new(0x4646, 0x8380); // TC = 1
        p.question("example.com", QTYPE_A);
        let bytes = p.finish();
        let qname: Name = "example.com".parse().unwrap();
        assert!(matches!(
            DnsMessage::parse_answer(&bytes, &qname, QTYPE_A),
            Err(QueryError::Malformed(_))
        ));
    }

    // -- negative TTL -----------------------------------------------------

    fn soa_rdata(minimum: u32) -> Vec<u8> {
        let mut rd = encode_name("ns.example.com");
        rd.extend_from_slice(&encode_name("hostmaster.example.com"));
        for v in [2024u32, 7200, 3600, 1_209_600, minimum] {
            rd.extend_from_slice(&v.to_be_bytes());
        }
        rd
    }

    #[test]
    fn negative_ttl_comes_from_soa_minimum_capped_by_record_ttl() {
        let mut p = Packet::new(0x5555, 0x8183); // NXDOMAIN
        p.question("nope.example.com", QTYPE_A);
        p.name("example.com").record(QTYPE_SOA, 900, &soa_rdata(45));
        p.authority();

        let msg = parse_ok(&p.finish());
        assert_eq!(msg.rcode(), RCODE_NXDOMAIN);
        assert_eq!(msg.negative_ttl(), Some(45));

        // The SOA record's own TTL below MINIMUM wins.
        let mut p2 = Packet::new(0x5556, 0x8183);
        p2.question("nope.example.com", QTYPE_A);
        p2.name("example.com").record(QTYPE_SOA, 5, &soa_rdata(45));
        p2.authority();
        assert_eq!(parse_ok(&p2.finish()).negative_ttl(), Some(5));

        // No SOA at all -> no advisory TTL (caller falls back to 10 s).
        let mut p3 = Packet::new(0x5557, 0x8183);
        p3.question("nope.example.com", QTYPE_A);
        assert_eq!(parse_ok(&p3.finish()).negative_ttl(), None);
    }

    #[test]
    fn nodata_response_still_reports_soa_ttl() {
        let mut p = Packet::new(0x5558, RESP_FLAGS); // NOERROR, no answers
        p.question("v6only.example.com", QTYPE_AAAA);
        p.name("example.com")
            .record(QTYPE_SOA, 600, &soa_rdata(120));
        p.authority();
        let msg = parse_ok(&p.finish());
        assert_eq!(msg.negative_ttl(), Some(120));
        let qname: Name = "v6only.example.com".parse().unwrap();
        assert_eq!(
            msg.answer(&qname, QTYPE_AAAA),
            Answer::Negative {
                rcode: 0,
                ttl: Some(120)
            }
        );
    }

    // -- robustness -------------------------------------------------------

    #[test]
    fn compression_pointer_loop_is_rejected() {
        // (a) A record owner name that points at itself.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes());
        buf.extend_from_slice(&RESP_FLAGS.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&encode_name("example.com"));
        buf.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        let ptr_at = buf.len() as u16;
        buf.extend_from_slice(&[0xC0 | (ptr_at >> 8) as u8, ptr_at as u8]);
        buf.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&60u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[192, 0, 2, 1]);
        assert_eq!(Message::parse(&buf), Err(ParseError::CompressionLoop));

        // (b) Two pointers pointing at each other (the second goes forward).
        let mut buf2 = Vec::new();
        buf2.extend_from_slice(&0x1234u16.to_be_bytes());
        buf2.extend_from_slice(&RESP_FLAGS.to_be_bytes());
        buf2.extend_from_slice(&1u16.to_be_bytes());
        buf2.extend_from_slice(&1u16.to_be_bytes());
        buf2.extend_from_slice(&0u16.to_be_bytes());
        buf2.extend_from_slice(&0u16.to_be_bytes());
        buf2.extend_from_slice(&encode_name("a"));
        buf2.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf2.extend_from_slice(&1u16.to_be_bytes());
        let first = buf2.len() as u16;
        let second = first + 2;
        buf2.extend_from_slice(&[0xC0, second as u8]);
        buf2.extend_from_slice(&[0xC0, first as u8]);
        buf2.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf2.extend_from_slice(&1u16.to_be_bytes());
        buf2.extend_from_slice(&60u32.to_be_bytes());
        buf2.extend_from_slice(&4u16.to_be_bytes());
        buf2.extend_from_slice(&[192, 0, 2, 1]);
        assert_eq!(Message::parse(&buf2), Err(ParseError::CompressionLoop));

        // (c) A pointer into the middle of a header must not produce a name.
        let mut buf3 = Vec::new();
        buf3.extend_from_slice(&0x1234u16.to_be_bytes());
        buf3.extend_from_slice(&RESP_FLAGS.to_be_bytes());
        buf3.extend_from_slice(&1u16.to_be_bytes());
        buf3.extend_from_slice(&1u16.to_be_bytes());
        buf3.extend_from_slice(&0u16.to_be_bytes());
        buf3.extend_from_slice(&0u16.to_be_bytes());
        buf3.extend_from_slice(&encode_name("a"));
        buf3.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf3.extend_from_slice(&1u16.to_be_bytes());
        buf3.extend_from_slice(&[0xC0, 0xFF]); // target 255 > packet length
        buf3.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf3.extend_from_slice(&1u16.to_be_bytes());
        buf3.extend_from_slice(&60u32.to_be_bytes());
        buf3.extend_from_slice(&4u16.to_be_bytes());
        buf3.extend_from_slice(&[192, 0, 2, 1]);
        assert!(
            matches!(
                Message::parse(&buf3),
                Err(ParseError::CompressionLoop) | Err(ParseError::BadPointer(_))
            ),
            "a pointer outside the packet must be rejected"
        );
    }

    #[test]
    fn truncated_packets_error_without_panicking() {
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("example.com", QTYPE_A);
        p.ptr_owner(12).record(QTYPE_A, 30, &[192, 0, 2, 1]);
        p.answer();
        let full = p.finish();

        // Every prefix must either parse or error, never panic.
        for cut in 0..full.len() {
            let _ = Message::parse(&full[..cut]);
            let _ = DnsMessage::parse_a_record(&full[..cut]);
            let _ = DnsMessage::parse_aaaa_record(&full[..cut]);
            let _ = DnsMessage::parse_ip_record(&full[..cut]);
            let _ = DnsMessage::parse_question(&full[..cut]);
            let _ = DnsMessage::parse_specific_record_with_ttl(&full[..cut], QTYPE_A);
        }
        assert!(Message::parse(&full[..11]).is_err());
        assert!(Message::parse(&[]).is_err());

        // rdlength pointing past the end of the packet.
        let mut bad = full.clone();
        let n = bad.len();
        bad[n - 6] = 0xFF;
        bad[n - 5] = 0xFF;
        assert!(matches!(
            Message::parse(&bad),
            Err(ParseError::Truncated(_)) | Ok(_)
        ));
    }

    #[test]
    fn oversized_section_counts_are_rejected() {
        let mut buf = vec![0x12, 0x34, 0x81, 0x80];
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            Message::parse(&buf),
            Err(ParseError::TooManyRecords("question"))
        );
    }

    #[test]
    fn reserved_label_types_are_rejected() {
        let mut buf = vec![0x12, 0x34, 0x81, 0x80];
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.push(0x80); // reserved label type
        buf.extend_from_slice(b"a\0");
        buf.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            Message::parse(&buf),
            Err(ParseError::ReservedLabelType(0x80))
        ));
    }

    // -- reverse names ----------------------------------------------------

    #[test]
    fn ptr_names_roundtrip_for_both_families() {
        let v4: IpAddr = "198.18.0.7".parse().unwrap();
        let n = ip_to_ptr_name(&v4);
        assert_eq!(n.to_string(), "7.0.18.198.in-addr.arpa");
        assert_eq!(ptr_name_to_ip(&n), Some(v4));

        let v6: IpAddr = "fc00::1234".parse().unwrap();
        let n6 = ip_to_ptr_name(&v6);
        assert!(n6.to_string().ends_with("ip6.arpa"));
        assert_eq!(ptr_name_to_ip(&n6), Some(v6));

        assert_eq!(ptr_name_to_ip(&"example.com".parse().unwrap()), None);
    }

    // -- builders ---------------------------------------------------------

    #[test]
    fn question_roundtrip() {
        let q = DnsMessage::build_query("example.com", QTYPE_A);
        let (id, flags, name, qtype, end) = DnsMessage::parse_question(&q).expect("parse");
        assert_eq!(id, u16::from_be_bytes([q[0], q[1]]));
        assert_eq!(flags & 0x0100, 0x0100, "RD must be set by the builder");
        assert_eq!(name, "example.com");
        assert_eq!(qtype, QTYPE_A);
        assert_eq!(end, q.len(), "question must span the whole query");
    }

    #[test]
    fn response_carries_the_answer() {
        let q = DnsMessage::build_query("fake.example", QTYPE_A);
        let ip = Ipv4Addr::new(198, 18, 0, 7);
        let r = DnsMessage::build_response(&q, Some(ip)).expect("response");
        assert_eq!(&r[..2], &q[..2]);
        assert_eq!(u16::from_be_bytes([r[2], r[3]]) & 0x8000, 0x8000, "QR set");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "one answer");
        assert_eq!(DnsMessage::parse_a_record(&r).ok(), Some(ip));
        assert_eq!(
            DnsMessage::parse_question(&r).map(|q| q.2),
            Some("fake.example".to_string())
        );
    }

    #[test]
    fn v6_and_ptr_responses_are_well_formed() {
        let q = DnsMessage::build_query("v6.example", QTYPE_AAAA);
        let v6: Ipv6Addr = "fc00::42".parse().unwrap();
        let r = DnsMessage::build_response_ip(&q, Some(IpAddr::V6(v6))).unwrap();
        assert_eq!(DnsMessage::parse_aaaa_record(&r).unwrap(), v6);
        assert_eq!(
            DnsMessage::parse_question(&r).map(|q| q.3),
            Some(QTYPE_AAAA)
        );

        let q2 = DnsMessage::build_query("7.0.18.198.in-addr.arpa", QTYPE_PTR);
        let target: Name = "example.com".parse().unwrap();
        let r2 = DnsMessage::build_response_ptr(&q2, &target).unwrap();
        let msg = Message::parse(&r2).unwrap();
        assert_eq!(msg.answers[0].rdata, RData::Ptr(target));
        assert_eq!(msg.answers[0].rtype, QTYPE_PTR);
    }

    #[test]
    fn nodata_response_has_no_answers() {
        let q = DnsMessage::build_query("v6only.example", QTYPE_AAAA);
        let r = DnsMessage::build_response(&q, None).expect("response");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no answers");
        assert!(DnsMessage::parse_a_record(&r).is_err());
    }

    #[test]
    fn malformed_queries_are_rejected() {
        assert!(DnsMessage::parse_question(&[]).is_none());
        assert!(DnsMessage::parse_question(&[0u8; 11]).is_none());
        // Compression pointer in the question name.
        let mut q = DnsMessage::build_query("a.example", QTYPE_A);
        q[12] = 0xC0;
        assert!(DnsMessage::parse_question(&q).is_none());
        // Truncated label.
        let mut q2 = DnsMessage::build_query("example.com", QTYPE_A);
        q2.truncate(14);
        assert!(DnsMessage::parse_question(&q2).is_none());
    }

    #[test]
    fn build_query_with_ecs() {
        let subnet: ipnet::IpNet = "192.0.2.0/24".parse().unwrap();
        let query = DnsMessage::build_query_with_ecs("example.com", QTYPE_A, Some(subnet));
        assert!(query.len() > 30);
        assert_eq!(query[11], 1); // ARCOUNT = 1
        assert!(query.windows(2).any(|w| w == [0x00, 0x08]));
        let msg = Message::parse(&query).unwrap();
        assert_eq!(msg.additional.len(), 1);
    }

    #[test]
    fn dual_a_and_aaaa_records_are_both_reachable() {
        let mut p = Packet::new(0x1234, RESP_FLAGS);
        p.question("example.com", QTYPE_A);
        p.ptr_owner(12).record(QTYPE_A, 300, &[192, 0, 2, 1]);
        p.answer();
        let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        p.ptr_owner(12).record(QTYPE_AAAA, 300, &ipv6.octets());
        p.answer();
        let bytes = p.finish();

        assert_eq!(
            DnsMessage::parse_a_record(&bytes).unwrap(),
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert_eq!(DnsMessage::parse_aaaa_record(&bytes).unwrap(), ipv6);
        assert_eq!(
            DnsMessage::parse_ip_record(&bytes).unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            "the legacy helper prefers IPv4"
        );
    }
}
