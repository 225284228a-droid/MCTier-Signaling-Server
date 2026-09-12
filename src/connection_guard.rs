use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use tokio_tungstenite::tungstenite::http::HeaderMap;

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

/// Privacy addresses on one IPv6 network must not multiply source quotas.
pub fn quota_source(ip: IpAddr) -> IpAddr {
    match canonical(ip) {
        IpAddr::V6(ip) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
        ip => ip,
    }
}

pub struct Admission {
    pub trusted_proxies: HashSet<IpAddr>,
    pending: Arc<Pool>,
    active: Arc<Pool>,
}

struct Pool {
    limit: usize,
    source_limit: usize,
    counts: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

pub struct Lease {
    pool: Arc<Pool>,
    source: Option<IpAddr>,
}

impl Pool {
    fn acquire(self: &Arc<Self>, source: Option<IpAddr>) -> Result<Lease, &'static str> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if counts.0 >= self.limit {
            return Err("connection capacity reached");
        }
        if let Some(ip) = source {
            if counts.1.get(&ip).copied().unwrap_or(0) >= self.source_limit {
                return Err("source connection capacity reached");
            }
            *counts.1.entry(ip).or_default() += 1;
        }
        counts.0 += 1;
        Ok(Lease {
            pool: Arc::clone(self),
            source,
        })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut counts = self.pool.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.0 -= 1;
        if let Some(ip) = self.source {
            if let Some(count) = counts.1.get_mut(&ip) {
                *count -= 1;
                if *count == 0 {
                    counts.1.remove(&ip);
                }
            }
        }
    }
}

impl Admission {
    pub fn new(max: usize, per_source: usize, proxies: &str) -> Result<Self, String> {
        let trusted_proxies = proxies
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.trim().parse::<IpAddr>().map(canonical).map_err(|_| {
                    "TRUSTED_PROXIES must contain comma-separated IP addresses".to_owned()
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;
        let pool = |limit, source_limit| {
            Arc::new(Pool {
                limit,
                source_limit,
                counts: Mutex::new((0, HashMap::new())),
            })
        };
        Ok(Self {
            trusted_proxies,
            // Handshakes cannot consume the established WebSocket pool.
            pending: pool(max.min(128).max(1), per_source.min(16).max(1)),
            active: pool(max.max(1), per_source.max(1).min(max.saturating_sub(1).max(1))),
        })
    }

    pub fn pending(&self, peer: IpAddr) -> Result<Lease, &'static str> {
        let peer = canonical(peer);
        self.pending
            .acquire((!self.trusted_proxies.contains(&peer)).then_some(quota_source(peer)))
    }

    pub fn active(&self, source: IpAddr) -> Result<Lease, &'static str> {
        self.active.acquire(Some(quota_source(source)))
    }

    pub fn source(&self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, &'static str> {
        let peer = canonical(peer);
        if !self.trusted_proxies.contains(&peer) {
            return Ok(peer);
        }
        // Walk from the nearest proxy. Never trust a client-supplied leftmost IP.
        if headers.contains_key("x-forwarded-for") {
            if headers.get_all("x-forwarded-for").iter().count() != 1 {
                return Err("ambiguous forwarded address");
            }
            let value = headers["x-forwarded-for"]
                .to_str()
                .map_err(|_| "invalid forwarded address")?;
            if value.len() > 1024 {
                return Err("forwarded chain too long");
            }
            let chain = value
                .split(',')
                .map(|s| s.trim().parse::<IpAddr>().map(canonical))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "invalid forwarded address")?;
            if chain.len() > 16 {
                return Err("forwarded chain too long");
            }
            let client = chain
                .into_iter()
                .rev()
                .find(|ip| !self.trusted_proxies.contains(ip))
                .ok_or("forwarded chain has no client address")?;
            // A proxy that overwrites X-Real-IP but forwards the client-supplied
            // X-Forwarded-For unchanged would otherwise let attackers pick their
            // own quota bucket. Fail closed on a conflicting client claim; a
            // trusted-proxy X-Real-IP only vouches for the previous hop and is
            // ignored, which keeps multi-tier trusted chains usable.
            match headers.get_all("x-real-ip").iter().count() {
                0 => {}
                1 => {
                    let real = headers["x-real-ip"]
                        .to_str()
                        .ok()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .map(canonical)
                        .ok_or("invalid real address")?;
                    if !self.trusted_proxies.contains(&real) && real != client {
                        return Err("conflicting forwarded address");
                    }
                }
                _ => return Err("ambiguous forwarded address"),
            }
            return Ok(client);
        }
        if headers.get_all("x-real-ip").iter().count() != 1 {
            return Err("trusted proxy must send client address");
        }
        headers["x-real-ip"]
            .to_str()
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .map(canonical)
            .filter(|ip| !self.trusted_proxies.contains(ip))
            .ok_or("invalid real address")
    }
}

pub fn admission() -> &'static Admission {
    static VALUE: OnceLock<Admission> = OnceLock::new();
    VALUE.get_or_init(|| {
        let max = super::max_connections();
        let limit = std::env::var("MAX_CONNECTIONS_PER_SOURCE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(128.min((max / 4).max(1)));
        Admission::new(
            max,
            limit,
            &std::env::var("TRUSTED_PROXIES").unwrap_or_default(),
        )
        .expect("invalid connection admission configuration")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_headers_cannot_spoof_source_and_trusted_chains_use_nearest_client() {
        let guard = Admission::new(16, 4, "127.0.0.1,::1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.1.1.1, 203.0.113.9, 127.0.0.1".parse().unwrap(),
        );
        assert_eq!(
            guard
                .source("192.0.2.7".parse().unwrap(), &headers)
                .unwrap()
                .to_string(),
            "192.0.2.7"
        );
        assert_eq!(
            guard
                .source("127.0.0.1".parse().unwrap(), &headers)
                .unwrap()
                .to_string(),
            "203.0.113.9"
        );
        headers.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert!(guard
            .source("127.0.0.1".parse().unwrap(), &headers)
            .is_err());
        assert!(guard
            .source("127.0.0.1".parse().unwrap(), &HeaderMap::new())
            .is_err());
    }

    #[test]
    fn forwarded_chain_must_agree_with_a_client_x_real_ip_vouch() {
        let guard = Admission::new(16, 4, "127.0.0.1,::1").unwrap();
        let mut headers = HeaderMap::new();
        // 报告场景：代理转发了客户端注入的 XFF，但同时写入了权威 X-Real-IP。
        // 两者冲突时必须拒绝，否则攻击者可自选配额桶绕过限流。
        headers.insert("x-forwarded-for", "198.51.100.23".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.7".parse().unwrap());
        assert_eq!(
            guard.source("127.0.0.1".parse().unwrap(), &headers)
                .unwrap_err(),
            "conflicting forwarded address"
        );
        // 一致的声明放行。
        headers.insert("x-forwarded-for", "192.0.2.7".parse().unwrap());
        assert_eq!(
            guard
                .source("127.0.0.1".parse().unwrap(), &headers)
                .unwrap()
                .to_string(),
            "192.0.2.7"
        );
        // 多层受信链：X-Real-IP 只为上一跳（受信代理）背书时忽略，不影响解析。
        let mut chained = HeaderMap::new();
        chained.insert("x-forwarded-for", "192.0.2.7, 198.51.100.8".parse().unwrap());
        chained.insert("x-real-ip", "127.0.0.1".parse().unwrap());
        assert_eq!(
            guard
                .source("127.0.0.1".parse().unwrap(), &chained)
                .unwrap()
                .to_string(),
            "198.51.100.8"
        );
        // 多个 X-Real-IP 与 XFF 并存同样视为歧义。
        let mut ambiguous = HeaderMap::new();
        ambiguous.insert("x-forwarded-for", "192.0.2.7".parse().unwrap());
        ambiguous.insert("x-real-ip", "192.0.2.7".parse().unwrap());
        ambiguous.append("x-real-ip", "198.51.100.23".parse().unwrap());
        assert_eq!(
            guard.source("127.0.0.1".parse().unwrap(), &ambiguous)
                .unwrap_err(),
            "ambiguous forwarded address"
        );
    }

    #[test]
    fn one_source_cannot_fill_pool_and_leases_recover_on_disconnect() {
        let guard = Admission::new(16, 4, "").unwrap();
        let ip = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..4).map(|_| guard.active(ip).unwrap()).collect();
        assert!(guard.active(ip).is_err());
        assert!(guard.active("192.0.2.2".parse().unwrap()).is_ok());
        assert!(guard.active("::ffff:192.0.2.1".parse().unwrap()).is_err());
        drop(held);
        assert!(guard.active(ip).is_ok());
        let pending: Vec<_> = (0..4).map(|_| guard.pending(ip).unwrap()).collect();
        assert!(guard.pending(ip).is_err());
        assert!(guard.active(ip).is_ok());
        drop(pending);
        assert!(guard.pending(ip).is_ok());
        let ipv6 = "2001:db8:1:2::1".parse().unwrap();
        let _v6: Vec<_> = (0..4).map(|_| guard.active(ipv6).unwrap()).collect();
        assert!(guard.active("2001:db8:1:2::ffff".parse().unwrap()).is_err());
        assert!(guard.active("2001:db8:1:3::1".parse().unwrap()).is_ok());
    }
}
