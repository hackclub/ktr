use std::fmt::Debug;
use std::io::{self, prelude::*, BufReader, Lines};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const WHOIS_PORT: u16 = 43;

#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Asn(pub u32);

impl Debug for Asn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", content = "asn"))] // Change if you add another field to the enum!
pub enum AsnResult {
    Pending,
    Found(Asn),
    NotFound,
}

/// ASN finder that tries multiple WHOIS servers.
#[derive(Debug)]
pub struct AsnFinder {
    iana: Option<NormalAsnServer>,
    radb: Option<NormalAsnServer>,
    cymru: Option<CymruAsnServer>,
}

impl AsnFinder {
    pub fn lookup(ip: IpAddr) -> Result<AsnFinder, io::Error> {
        Ok(Self {
            iana: NormalAsnServer::connect(ip, "whois.iana.org").ok(),
            radb: NormalAsnServer::connect(ip, "whois.radb.net").ok(),
            cymru: CymruAsnServer::connect(ip).ok(),
        })
    }

    pub fn poll(&mut self) -> Result<AsnResult, io::Error> {
        let results = [
            self.iana
                .as_mut()
                .and_then(|s| s.poll().ok())
                .unwrap_or(AsnResult::NotFound),
            self.radb
                .as_mut()
                .and_then(|s| s.poll().ok())
                .unwrap_or(AsnResult::NotFound),
            self.cymru
                .as_mut()
                .and_then(|s| s.poll().ok())
                .unwrap_or(AsnResult::NotFound),
        ];

        for result in results {
            if let AsnResult::Found(asn) = result {
                return Ok(AsnResult::Found(asn));
            }
        }
        if results
            .into_iter()
            .all(|result| matches!(result, AsnResult::NotFound))
        {
            return Ok(AsnResult::NotFound);
        }
        Ok(AsnResult::Pending)
    }
}

trait AsnServer {
    fn poll(&mut self) -> Result<AsnResult, io::Error>;
}

/// Normal WHOIS server (colon-separated lines).
#[derive(Debug)]
struct NormalAsnServer {
    ip: IpAddr,
    lines: Lines<BufReader<TcpStream>>,
    // Highest precendence for originas line so we return right away if we get that.
    // Otherwise, we wait until the end and use origin, refer, and whois in that order.
    // If we don't find any of those, we're screwed.
    line_origin: Option<Asn>,
    line_refer: Option<String>,
    line_whois: Option<String>,
}

impl NormalAsnServer {
    pub fn connect(ip: IpAddr, server: &str) -> Result<Self, io::Error> {
        let lines = BufReader::new(whois_connect(ip, server)?).lines();
        Ok(Self {
            ip,
            lines,
            line_origin: None,
            line_refer: None,
            line_whois: None,
        })
    }
}

impl AsnServer for NormalAsnServer {
    fn poll(&mut self) -> Result<AsnResult, io::Error> {
        match self.lines.next() {
            Some(Ok(line)) => {
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim();
                    let value = value.trim();
                    if key.eq_ignore_ascii_case("originas") {
                        if let Some(asn) = try_parse_asn_ignore_prefix(value) {
                            return Ok(AsnResult::Found(asn));
                        }
                    } else if key.eq_ignore_ascii_case("origin") {
                        if let Some(asn) = try_parse_asn_ignore_prefix(value) {
                            self.line_origin = Some(asn);
                        }
                    } else if key.eq_ignore_ascii_case("refer") {
                        self.line_refer = Some(value.to_string());
                    } else if key.eq_ignore_ascii_case("whois") {
                        self.line_whois = Some(value.to_string());
                    }
                }
            }
            Some(Err(error)) => {
                if error.kind() != io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut
                {
                    return Err(error);
                }
            }
            None => {
                if let Some(asn) = self.line_origin {
                    return Ok(AsnResult::Found(asn));
                } else if let Some(ref refer) = self.line_refer {
                    *self = Self::connect(self.ip, refer)?;
                } else if let Some(ref whois) = self.line_whois {
                    *self = Self::connect(self.ip, whois)?;
                } else {
                    return Ok(AsnResult::NotFound);
                }
            }
        }
        Ok(AsnResult::Pending)
    }
}

/// Cymru WHOIS server.
#[derive(Debug)]
struct CymruAsnServer {
    lines: Lines<BufReader<TcpStream>>,
}

impl CymruAsnServer {
    pub fn connect(ip: IpAddr) -> Result<Self, io::Error> {
        let lines = BufReader::new(whois_connect(ip, "whois.cymru.com")?).lines();
        Ok(Self { lines })
    }
}

impl AsnServer for CymruAsnServer {
    fn poll(&mut self) -> Result<AsnResult, io::Error> {
        match self.lines.next() {
            Some(Ok(line)) => {
                if let Some((asn, _)) = line.split_once('|') {
                    Ok(try_parse_asn_unprefixed(asn.trim())
                        .map_or(AsnResult::Pending, AsnResult::Found))
                } else {
                    Ok(AsnResult::Pending)
                }
            }
            Some(Err(error)) => {
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut
                {
                    Ok(AsnResult::Pending)
                } else {
                    Err(error)
                }
            }
            None => Ok(AsnResult::NotFound),
        }
    }
}

fn try_parse_asn_unprefixed(text: &str) -> Option<Asn> {
    text.trim().parse().ok().map(Asn)
}

fn try_parse_asn_prefixed(text: &str) -> Option<Asn> {
    let (_, num) = text.split_once("AS")?;
    try_parse_asn_unprefixed(num)
}

fn try_parse_asn_ignore_prefix(text: &str) -> Option<Asn> {
    try_parse_asn_prefixed(text).or_else(|| try_parse_asn_unprefixed(text))
}

fn whois_connect(ip: IpAddr, server: &str) -> Result<TcpStream, io::Error> {
    let addr = (server, WHOIS_PORT)
        .to_socket_addrs()?
        .next()
        .ok_or(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "No DNS address found for WHOIS server",
        ))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_millis(50)))?;
    stream.set_write_timeout(Some(Duration::from_millis(50)))?;
    stream.set_nonblocking(true)?;

    stream.write_all(ip.to_string().as_bytes())?;
    stream.write_all(b"\r\n")?;

    Ok(stream)
}
