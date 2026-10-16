//! Fase 37 — process-global DNS cache.
//!
//! Reverse (PTR) lookups were previously done with a fresh `hickory` resolver
//! per call-site, so each phase re-resolved the same IPs and built its own
//! cache. This memoises reverse lookups process-wide behind a single resolver,
//! so a repeated IP — across `-R`, `-sL`, cloud-fingerprint, reporting — is a
//! cache hit instead of another round-trip. The cache core is a pure,
//! unit-tested map; the async wrapper adds the shared resolver.

use hickory_resolver::TokioAsyncResolver;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

/// Pure reverse-DNS memo with hit/miss counters.
#[derive(Default)]
pub struct DnsCache {
    reverse: HashMap<IpAddr, Option<String>>,
    hits: u64,
    misses: u64,
}

impl DnsCache {
    /// `Some(entry)` when the IP is cached (the entry itself may be `None` =
    /// "resolved to nothing"); `None` when never looked up. Updates counters.
    pub fn lookup(&mut self, ip: &IpAddr) -> Option<Option<String>> {
        match self.reverse.get(ip) {
            Some(v) => {
                self.hits += 1;
                Some(v.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    pub fn store(&mut self, ip: IpAddr, name: Option<String>) {
        self.reverse.insert(ip, name);
    }

    /// (hits, misses) — surfaced for perf diagnostics.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

static CACHE: OnceLock<Mutex<DnsCache>> = OnceLock::new();
fn cache() -> &'static Mutex<DnsCache> {
    CACHE.get_or_init(|| Mutex::new(DnsCache::default()))
}

static RESOLVER: OnceLock<Option<TokioAsyncResolver>> = OnceLock::new();
fn resolver() -> &'static Option<TokioAsyncResolver> {
    RESOLVER.get_or_init(|| TokioAsyncResolver::tokio_from_system_conf().ok())
}

/// Reverse-resolve an IP to a PTR hostname, memoised process-wide. A repeated
/// IP returns the cached answer without touching the resolver again.
pub async fn reverse(ip: IpAddr) -> Option<String> {
    if let Some(cached) = cache().lock().unwrap().lookup(&ip) {
        return cached;
    }
    let name = match resolver() {
        Some(r) => r.reverse_lookup(ip).await.ok().and_then(|l| {
            l.iter()
                .next()
                .map(|n| n.to_string().trim_end_matches('.').to_string())
        }),
        None => None,
    };
    cache().lock().unwrap().store(ip, name.clone());
    name
}

/// Process-wide (hits, misses) for the reverse-DNS cache.
pub fn global_stats() -> (u64, u64) {
    cache().lock().unwrap().stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_then_hit_counts() {
        let mut c = DnsCache::default();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // First lookup: miss.
        assert!(c.lookup(&ip).is_none());
        c.store(ip, Some("router.lan".into()));
        // Second lookup: hit, returns the stored name.
        assert_eq!(c.lookup(&ip), Some(Some("router.lan".into())));
        let (hits, misses) = c.stats();
        assert_eq!((hits, misses), (1, 1));
    }

    #[test]
    fn caches_negative_answers() {
        let mut c = DnsCache::default();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        c.lookup(&ip); // miss
        c.store(ip, None); // resolved to nothing
        // A cached negative is still a hit (no re-resolve).
        assert_eq!(c.lookup(&ip), Some(None));
        assert_eq!(c.stats(), (1, 1));
    }
}
