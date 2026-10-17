// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! The capture filter for the built-in Linux capture, which works without libpcap.
//!
//! It understands the common part of libpcap's filter language, with the same
//! meaning: `not` binds tightest, and `and` / `or` have equal precedence and group
//! left to right (so `a or b and c` means `(a or b) and c`, as in tcpdump).
//!
//! ```text
//! tcp  udp  icmp  icmp6  arp  ip  ip6
//! [tcp|udp] [src|dst] port N          [tcp|udp] [src|dst] portrange N-M
//! [src|dst] host ADDRESS              [src|dst] net ADDRESS/BITS
//! not ...   ... and ...   ... or ...   ( ... )      (also ! && ||)
//! ```
//!
//! Anything else is refused with a message that lists the supported forms, so a
//! filter never silently means something different from what was typed.

use std::net::IpAddr;

use crate::decode::{Summary, L3};

/// The forms the built-in filter understands, for error messages and docs.
pub const SUPPORTED: &str = "tcp, udp, icmp, icmp6, arp, ip, ip6, \
[tcp|udp] [src|dst] port N, [tcp|udp] [src|dst] portrange N-M, \
[src|dst] host ADDRESS, [src|dst] net ADDRESS/BITS, not, and, or, ( )";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Either,
    Src,
    Dst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Prim {
    L3(L3),
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6).
    L4(u8),
    Port {
        dir: Dir,
        /// Restrict to TCP or UDP; `None` = TCP, UDP or SCTP, as libpcap does.
        l4: Option<u8>,
        lo: u16,
        hi: u16,
    },
    Host {
        dir: Dir,
        addr: IpAddr,
    },
    Net {
        dir: Dir,
        net: IpAddr,
        bits: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Prim(Prim),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

/// A parsed filter, ready to test packets against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    expr: Expr,
}

impl Filter {
    /// Parse a filter. The error names the problem and lists what is supported.
    pub fn parse(text: &str) -> Result<Self, String> {
        let tokens = tokenize(text);
        if tokens.is_empty() {
            return Err(fail(text, "it is empty"));
        }
        let mut p = Parser {
            tokens: &tokens,
            pos: 0,
            text,
        };
        let expr = p.expr()?;
        if let Some(t) = p.peek() {
            return Err(fail(text, &format!("unexpected {t:?}")));
        }
        Ok(Self { expr })
    }

    /// Does this packet pass the filter?
    pub fn matches(&self, s: &Summary) -> bool {
        eval(&self.expr, s)
    }
}

fn fail(text: &str, why: &str) -> String {
    format!("--filter {text:?}: {why}. The built-in Linux capture understands: {SUPPORTED}")
}

fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars().peekable();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => flush(&mut cur, &mut out),
            '(' | ')' => {
                flush(&mut cur, &mut out);
                out.push(c.to_string());
            }
            '!' => {
                flush(&mut cur, &mut out);
                out.push("not".to_string());
            }
            '&' | '|' if chars.peek() == Some(&c) => {
                chars.next();
                flush(&mut cur, &mut out);
                out.push(if c == '&' { "and" } else { "or" }.to_string());
            }
            c => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    out
}

struct Parser<'a> {
    tokens: &'a [String],
    pos: usize,
    text: &'a str,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(String::as_str)
    }

    fn peek_kw(&self) -> Option<String> {
        self.peek().map(str::to_ascii_lowercase)
    }

    fn next(&mut self) -> Option<&str> {
        let t = self.tokens.get(self.pos).map(String::as_str);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn err(&self, why: &str) -> String {
        fail(self.text, why)
    }

    /// expr := unary ((and | or) unary)*, left to right with equal precedence.
    fn expr(&mut self) -> Result<Expr, String> {
        let mut left = self.unary()?;
        while let Some(op) = self.peek_kw() {
            match op.as_str() {
                "and" => {
                    self.pos += 1;
                    let right = self.unary()?;
                    left = Expr::And(Box::new(left), Box::new(right));
                }
                "or" => {
                    self.pos += 1;
                    let right = self.unary()?;
                    left = Expr::Or(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek_kw().as_deref() {
            None => Err(self.err("it ends too early")),
            Some("not") => {
                self.pos += 1;
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            Some("(") => {
                self.pos += 1;
                let e = self.expr()?;
                match self.next() {
                    Some(")") => Ok(e),
                    _ => Err(self.err("a \"(\" is never closed")),
                }
            }
            Some(_) => Ok(Expr::Prim(self.primitive()?)),
        }
    }

    fn primitive(&mut self) -> Result<Prim, String> {
        let first = self.peek_kw().unwrap_or_default();
        // A protocol word on its own, or as a qualifier in front of port/host/net.
        let proto: Option<Prim> = match first.as_str() {
            "tcp" => Some(Prim::L4(6)),
            "udp" => Some(Prim::L4(17)),
            "icmp" => Some(Prim::L4(1)),
            "icmp6" => Some(Prim::L4(58)),
            "arp" => Some(Prim::L3(L3::Arp)),
            "ip" => Some(Prim::L3(L3::Ip4)),
            "ip6" => Some(Prim::L3(L3::Ip6)),
            _ => None,
        };
        let mut l4 = None;
        if let Some(p) = proto {
            self.pos += 1;
            let qualified = matches!(
                self.peek_kw().as_deref(),
                Some("src" | "dst" | "port" | "portrange" | "host" | "net")
            );
            if !qualified {
                return Ok(p);
            }
            match first.as_str() {
                "tcp" => l4 = Some(6),
                "udp" => l4 = Some(17),
                // "ip host X" / "ip6 net Y": the address already says which family.
                "ip" | "ip6" => {}
                _ => return Err(self.err(&format!("{first:?} can't qualify port, host or net"))),
            }
        }
        let dir = match self.peek_kw().as_deref() {
            Some("src") => {
                self.pos += 1;
                Dir::Src
            }
            Some("dst") => {
                self.pos += 1;
                Dir::Dst
            }
            _ => Dir::Either,
        };
        let kind = self.peek_kw();
        let Some(kind) = kind else {
            return Err(self.err("it ends too early"));
        };
        self.pos += 1;
        let Some(value) = self.next().map(str::to_string) else {
            return Err(self.err(&format!("{kind:?} needs a value after it")));
        };
        match kind.as_str() {
            "port" => {
                let n = parse_port(&value).ok_or_else(|| {
                    self.err(&format!("port {value:?} isn't a number from 0 to 65535"))
                })?;
                Ok(Prim::Port {
                    dir,
                    l4,
                    lo: n,
                    hi: n,
                })
            }
            "portrange" => {
                let (a, b) = value
                    .split_once('-')
                    .and_then(|(a, b)| Some((parse_port(a)?, parse_port(b)?)))
                    .ok_or_else(|| {
                        self.err(&format!("portrange {value:?} should look like 6000-6010"))
                    })?;
                Ok(Prim::Port {
                    dir,
                    l4,
                    lo: a.min(b),
                    hi: a.max(b),
                })
            }
            "host" => {
                let addr: IpAddr = value.parse().map_err(|_| {
                    self.err(&format!(
                        "host {value:?} isn't an IP address (names are not looked up)"
                    ))
                })?;
                Ok(Prim::Host { dir, addr })
            }
            "net" => {
                let (a, bits) = match value.split_once('/') {
                    Some((a, b)) => (a, Some(b)),
                    None => (value.as_str(), None),
                };
                let net: IpAddr = a.parse().map_err(|_| {
                    self.err(&format!("net {value:?} should look like 192.168.0.0/16"))
                })?;
                let max = if net.is_ipv4() { 32 } else { 128 };
                let bits = match bits {
                    Some(b) => b
                        .parse::<u8>()
                        .ok()
                        .filter(|&b| b <= max)
                        .ok_or_else(|| self.err(&format!("net {value:?} has a bad /bits")))?,
                    None => max,
                };
                Ok(Prim::Net {
                    dir,
                    net: mask(net, bits),
                    bits,
                })
            }
            other => Err(self.err(&format!("{other:?} isn't supported"))),
        }
    }
}

fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Keep the top `bits` bits of an address.
fn mask(addr: IpAddr, bits: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let m = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
}

fn in_net(addr: IpAddr, net: IpAddr, bits: u8) -> bool {
    addr.is_ipv4() == net.is_ipv4() && mask(addr, bits) == net
}

fn by_dir<T: Copy>(dir: Dir, src: Option<T>, dst: Option<T>, test: impl Fn(T) -> bool) -> bool {
    let s = src.is_some_and(&test);
    let d = dst.is_some_and(&test);
    match dir {
        Dir::Either => s || d,
        Dir::Src => s,
        Dir::Dst => d,
    }
}

fn eval(e: &Expr, s: &Summary) -> bool {
    match e {
        Expr::Not(x) => !eval(x, s),
        Expr::And(a, b) => eval(a, s) && eval(b, s),
        Expr::Or(a, b) => eval(a, s) || eval(b, s),
        Expr::Prim(p) => match p {
            Prim::L3(l3) => s.l3 == *l3,
            Prim::L4(n) => {
                // icmp is IPv4-only and icmp6 IPv6-only, as in libpcap.
                let family_ok = match n {
                    1 => s.l3 == L3::Ip4,
                    58 => s.l3 == L3::Ip6,
                    _ => true,
                };
                family_ok && s.l4 == Some(*n)
            }
            Prim::Port { dir, l4, lo, hi } => {
                let proto_ok = match l4 {
                    Some(n) => s.l4 == Some(*n),
                    None => matches!(s.l4, Some(6 | 17 | 132)),
                };
                proto_ok && by_dir(*dir, s.sport, s.dport, |p| (*lo..=*hi).contains(&p))
            }
            Prim::Host { dir, addr } => by_dir(*dir, s.src, s.dst, |a| a == *addr),
            Prim::Net { dir, net, bits } => by_dir(*dir, s.src, s.dst, |a| in_net(a, *net, *bits)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(l4: u8, src: &str, sport: u16, dst: &str, dport: u16) -> Summary {
        let src: IpAddr = src.parse().unwrap();
        Summary {
            l3: if src.is_ipv4() { L3::Ip4 } else { L3::Ip6 },
            l4: Some(l4),
            src: Some(src),
            dst: Some(dst.parse().unwrap()),
            sport: Some(sport),
            dport: Some(dport),
        }
    }

    fn yes(f: &str, s: &Summary) -> bool {
        Filter::parse(f)
            .unwrap_or_else(|e| panic!("{e}"))
            .matches(s)
    }

    #[test]
    fn protocols_ports_hosts_nets() {
        let dns = pkt(17, "10.0.0.2", 53111, "1.1.1.1", 53);
        let web = pkt(6, "10.0.0.2", 51514, "93.184.216.34", 443);
        let v6 = pkt(6, "fe80::1", 40000, "fe80::2", 22);
        assert!(yes("udp", &dns) && !yes("tcp", &dns));
        assert!(yes("udp port 53", &dns) && !yes("tcp port 53", &dns));
        assert!(yes("port 53", &dns) && yes("dst port 53", &dns) && !yes("src port 53", &dns));
        assert!(yes("portrange 400-500", &web) && !yes("portrange 1-100", &web));
        assert!(yes("host 1.1.1.1", &dns) && yes("dst host 1.1.1.1", &dns));
        assert!(!yes("src host 1.1.1.1", &dns));
        assert!(yes("net 10.0.0.0/8", &dns) && yes("src net 10.0.0.0/8", &web));
        assert!(!yes("dst net 10.0.0.0/8", &web));
        assert!(yes("ip", &dns) && !yes("ip6", &dns) && yes("ip6", &v6));
        assert!(yes("tcp port 22", &v6) && yes("net fe80::/10", &v6));
        assert!(yes("ip host 1.1.1.1", &dns));
        // A mask with host bits set is narrowed to its network.
        assert!(yes("net 10.9.9.9/8", &dns));
    }

    #[test]
    fn boolean_logic_matches_libpcap_precedence() {
        let dns = pkt(17, "10.0.0.2", 53111, "1.1.1.1", 53);
        assert!(yes("not tcp", &dns) && yes("! tcp", &dns));
        assert!(yes("udp and port 53", &dns) && yes("udp && port 53", &dns));
        assert!(yes("tcp or udp", &dns) && yes("tcp || udp", &dns));
        // Equal precedence, left to right: (udp or tcp) and port 80 -> false.
        assert!(!yes("udp or tcp and port 80", &dns));
        // Parentheses change it: udp or (tcp and port 80) -> true.
        assert!(yes("udp or (tcp and port 80)", &dns));
        assert!(yes("not (tcp or arp)", &dns));
        assert!(yes("UDP PORT 53", &dns), "keywords ignore case");
    }

    #[test]
    fn icmp_arp_and_missing_fields() {
        let mut ping = pkt(1, "10.0.0.2", 0, "10.0.0.1", 0);
        ping.sport = None;
        ping.dport = None;
        assert!(yes("icmp", &ping) && !yes("icmp6", &ping));
        assert!(!yes("port 0", &ping), "ICMP has no ports");
        let arp = Summary {
            l3: L3::Arp,
            ..Summary::default()
        };
        assert!(yes("arp", &arp) && !yes("ip", &arp) && !yes("host 10.0.0.1", &arp));
        assert!(yes("not ip and not ip6", &arp));
    }

    #[test]
    fn unsupported_forms_are_refused_clearly() {
        for bad in [
            "",
            "port",
            "port http",
            "port 70000",
            "host example.com",
            "ether host 00:11:22:33:44:55",
            "tcp[13] & 2 != 0",
            "net 10.0.0.0/40",
            "(udp",
            "udp)",
            "udp port 53 or 80",
            "portrange 10",
            "arp port 53",
            "udp and",
        ] {
            let e = Filter::parse(bad).expect_err(bad);
            assert!(e.contains("--filter"), "{bad}: {e}");
            assert!(
                e.contains("understands"),
                "{bad}: lists the supported forms: {e}"
            );
        }
    }
}
