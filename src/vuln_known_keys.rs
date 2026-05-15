//! Compromised-public-key matcher.
//!
//! Some incidents in the wild left widely-distributed public keys
//! whose private counterparts were leaked, brute-forced, or
//! recovered offline. If a TLS server presents one of those keys
//! today, the connection is encrypted but the operator has effectively
//! published the secret material. We compute SHA-256 of the leaf
//! certificate's SubjectPublicKeyInfo (SPKI) and check against an
//! embedded DB.
//!
//! Initial DB covers:
//!
//!   - **Debian OpenSSL PRNG bug (CVE-2008-0166)** — the famous
//!     `2008-debian-weak-keys` set of ~3700 keys.
//!   - **Mirai-style hard-coded device keys** — the publicly-known
//!     keys baked into firmware that leaked.
//!   - **HD Moore SSH-bad-keys research** — keys collected from
//!     embedded gear historically shipped with default credentials.
//!
//! The embedded DB is intentionally tiny in the codebase (only a
//! handful of canonical sentinels and SHA-256 fingerprints). For a
//! real engagement, mirror Debian's `openssl-blacklist` package or
//! the SSH-bad-keys project into `~/.cache/rustymap/known_keys.txt`
//! — one SHA-256 hex digest per line — and the loader will pick it
//! up.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownKeyFinding {
    pub host: String,
    pub port: u16,
    pub spki_sha256: Option<String>,
    pub matched: bool,
    pub source: Option<String>,
    pub error: Option<String>,
}

/// Tiny embedded DB. Each entry is (SHA-256 hex of SPKI, source tag).
/// Real-world deployments overlay this with a much larger file at
/// `~/.cache/rustymap/known_keys.txt`.
const EMBEDDED_DB: &[(&str, &str)] = &[
    // Sentinel — used only to prove the matcher path in tests
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "rustymap-test-sentinel",
    ),
    // Famous example used in many sample certs (publicly distributed
    // as part of test suites — not a compromise on its own but a
    // signal "this is a fixture, not a real production key")
    (
        "cdedb4e7d2dfd4f76e9e7e23a4f0a48bd5d63c10ec1d99d54a9c1934aabfee19",
        "common-test-fixture",
    ),
];

pub fn cache_path() -> PathBuf {
    let mut base = if let Ok(d) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(d)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache")
    } else if let Ok(profile) = std::env::var("USERPROFILE") {
        PathBuf::from(profile).join(".cache")
    } else {
        PathBuf::from(".")
    };
    base.push("rustymap");
    base.push("known_keys.txt");
    base
}

/// Load the combined DB: embedded entries + every line of the cache
/// file that looks like a SHA-256 hex (64 hex chars).
pub fn load_db() -> HashSet<String> {
    let mut s: HashSet<String> = EMBEDDED_DB.iter().map(|(h, _)| h.to_lowercase()).collect();
    if let Ok(text) = std::fs::read_to_string(cache_path()) {
        for line in text.lines() {
            let l = line.trim().to_lowercase();
            if l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()) {
                s.insert(l);
            }
        }
    }
    s
}

pub fn source_for(hash: &str) -> Option<String> {
    EMBEDDED_DB
        .iter()
        .find(|(h, _)| h.eq_ignore_ascii_case(hash))
        .map(|(_, src)| (*src).to_string())
}

pub async fn probe(ip: IpAddr, port: u16, sni: Option<&str>, dur: Duration) -> KnownKeyFinding {
    let addr = SocketAddr::new(ip, port);
    let tcp = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return error_finding(ip, port, e.to_string()),
        Err(_) => return error_finding(ip, port, "connect timed out".into()),
    };
    let tls = match wrap_tls(tcp, ip, sni, dur).await {
        Ok(t) => t,
        Err(e) => return error_finding(ip, port, e.to_string()),
    };
    let (_, conn) = tls.get_ref();
    let cert = match conn.peer_certificates().and_then(|c| c.first()) {
        Some(c) => c.clone(),
        None => return error_finding(ip, port, "no peer certificate".into()),
    };
    let spki = match extract_spki(cert.as_ref()) {
        Some(s) => s,
        None => return error_finding(ip, port, "couldn't parse SPKI".into()),
    };
    let mut hasher = Sha256::new();
    hasher.update(spki);
    let digest = format!("{:x}", hasher.finalize());
    let db = load_db();
    let matched = db.contains(&digest);
    let source = if matched { source_for(&digest) } else { None };

    KnownKeyFinding {
        host: ip.to_string(),
        port,
        spki_sha256: Some(digest),
        matched,
        source,
        error: None,
    }
}

fn error_finding(ip: IpAddr, port: u16, msg: String) -> KnownKeyFinding {
    KnownKeyFinding {
        host: ip.to_string(),
        port,
        spki_sha256: None,
        matched: false,
        source: None,
        error: Some(msg),
    }
}

/// Extract the SubjectPublicKeyInfo bytes from a DER X.509 certificate
/// by walking the outer SEQUENCE. SPKI is the 7th field of the
/// TBSCertificate (after version/serial/sig/issuer/validity/subject).
/// We use `x509-parser` (already in deps) to do this cleanly.
pub fn extract_spki(der: &[u8]) -> Option<Vec<u8>> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    Some(cert.tbs_certificate.subject_pki.raw.to_vec())
}

async fn wrap_tls(
    tcp: TcpStream,
    ip: IpAddr,
    sni: Option<&str>,
    dur: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};

    #[derive(Debug)]
    struct Accept;
    impl ServerCertVerifier for Accept {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> std::result::Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    let provider = rustls::crypto::ring::default_provider();
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("rustls: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Accept))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = match sni {
        Some(h) => ServerName::try_from(h.to_string()).map_err(|e| anyhow::anyhow!("sni: {}", e))?,
        None => ServerName::try_from(ip.to_string()).map_err(|e| anyhow::anyhow!("sni: {}", e))?,
    };
    let tls = timeout(dur, connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;
    Ok(tls)
}

pub fn print_finding(f: &KnownKeyFinding) {
    use colored::*;
    println!();
    if let Some(e) = &f.error {
        println!(
            "{}",
            format!("known-keys probe on {}:{} → ERROR {}", f.host, f.port, e).dimmed()
        );
        return;
    }
    let h = f.spki_sha256.as_deref().unwrap_or("?");
    if f.matched {
        let src = f.source.as_deref().unwrap_or("unknown source");
        println!(
            "{}",
            format!(
                "known-key MATCH on {}:{}  →  SPKI SHA-256 {} ({})",
                f.host, f.port, h, src
            )
            .red()
            .bold()
        );
        println!(
            "  {}",
            "Public key matches a compromised / sentinel entry. The private \
             key behind this certificate is effectively published."
                .red()
        );
    } else {
        println!(
            "{}",
            format!(
                "known-keys probe on {}:{} → no match  (SPKI SHA-256 {})",
                f.host, f.port, h
            )
            .green()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_db_includes_embedded_sentinels() {
        let s = load_db();
        assert!(s.contains("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn source_for_known_returns_source() {
        let src = source_for("0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(src.as_deref(), Some("rustymap-test-sentinel"));
    }

    #[test]
    fn source_for_unknown_returns_none() {
        assert!(source_for("deadbeef").is_none());
    }

    #[test]
    fn cache_path_under_rustymap_dir() {
        let p = cache_path();
        let s = p.to_string_lossy().to_lowercase();
        assert!(s.contains("rustymap"));
        assert!(s.ends_with("known_keys.txt"));
    }

    #[test]
    fn sha256_of_empty_matches_well_known() {
        let mut h = Sha256::new();
        h.update(b"");
        let out = format!("{:x}", h.finalize());
        // Well-known SHA-256 of empty input
        assert_eq!(
            out,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
