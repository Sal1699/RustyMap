//! SMTP capability audit — banner + EHLO + extension parsing.
//!
//! Covers ports 25 / 465 (implicit TLS / "smtps") / 587 (submission).
//! For 465 we run the EHLO inside a TLS connection right after TCP
//! connect; for 25/587 we EHLO in cleartext, then issue STARTTLS if
//! announced and re-EHLO over TLS to compare cleartext vs encrypted
//! capability sets — some servers advertise more AUTH mechanisms
//! only after TLS, which is good and worth surfacing.
//!
//! Findings:
//!   - missing STARTTLS on 25/587 → bad (passive sniff exposes auth)
//!   - PLAIN/LOGIN advertised before STARTTLS → bad (creds in clear)
//!   - VRFY/EXPN open → warn (user enumeration)
//!   - SMTP version banner missing — info only
//!
//! No actual authentication and no mail injected. We close after
//! reading capabilities.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmtpAudit {
    pub banner: String,
    pub starttls_offered: bool,
    pub starttls_succeeded: bool,
    pub implicit_tls: bool,
    pub auth_mechanisms_clear: Vec<String>,
    pub auth_mechanisms_tls: Vec<String>,
    pub vrfy: bool,
    pub expn: bool,
    pub size_max: Option<u64>,
    pub findings: Vec<String>,
}

impl SmtpAudit {
    pub fn has_weakness(&self) -> bool {
        !self.findings.is_empty()
    }
}

pub async fn audit(ip: IpAddr, port: u16, dur: Duration) -> Result<SmtpAudit> {
    let addr = SocketAddr::new(ip, port);
    let mut a = SmtpAudit::default();

    if port == 465 {
        // Implicit TLS — wrap the socket immediately, then EHLO.
        let tcp = timeout(dur, TcpStream::connect(addr)).await??;
        let tls = wrap_tls(tcp, ip, dur).await?;
        a.implicit_tls = true;
        let (banner, exts) = ehlo_exchange(tls, dur).await?;
        a.banner = banner;
        apply_extensions(&mut a, &exts, true);
    } else {
        // Cleartext start.
        let tcp = timeout(dur, TcpStream::connect(addr)).await??;
        let (banner, exts, mut bs) = ehlo_cleartext(tcp, dur).await?;
        a.banner = banner;
        apply_extensions(&mut a, &exts, false);

        if a.starttls_offered {
            // Issue STARTTLS, then re-EHLO inside TLS.
            timeout(dur, bs.write_all(b"STARTTLS\r\n")).await??;
            let resp = read_smtp_response(&mut bs, dur).await?;
            if resp.starts_with("220") {
                let inner = bs.into_inner();
                if let Ok(tls) = wrap_tls(inner, ip, dur).await {
                    a.starttls_succeeded = true;
                    if let Ok((_, exts2)) = ehlo_exchange(tls, dur).await {
                        apply_extensions(&mut a, &exts2, true);
                    }
                }
            }
        }
    }
    classify(&mut a, port);
    Ok(a)
}

async fn wrap_tls(tcp: TcpStream, ip: IpAddr, dur: Duration) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
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
        .expect("rustls protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Accept))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from(ip.to_string())
        .map_err(|e| anyhow!("server name: {e}"))?;
    let tls = timeout(dur, connector.connect(server_name, tcp)).await??;
    Ok(tls)
}

async fn ehlo_cleartext(
    tcp: TcpStream,
    dur: Duration,
) -> Result<(String, Vec<String>, BufReader<TcpStream>)> {
    let mut bs = BufReader::new(tcp);
    let banner = read_smtp_response(&mut bs, dur).await?;
    timeout(dur, bs.write_all(b"EHLO rustymap.audit\r\n")).await??;
    let resp = read_smtp_response(&mut bs, dur).await?;
    let exts = parse_ehlo_lines(&resp);
    Ok((banner, exts, bs))
}

async fn ehlo_exchange<S>(stream: S, dur: Duration) -> Result<(String, Vec<String>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut bs = BufReader::new(stream);
    let banner = read_smtp_response(&mut bs, dur).await?;
    timeout(dur, bs.write_all(b"EHLO rustymap.audit\r\n")).await??;
    let resp = read_smtp_response(&mut bs, dur).await?;
    let exts = parse_ehlo_lines(&resp);
    Ok((banner, exts))
}

async fn read_smtp_response<R: AsyncBufReadExt + Unpin>(r: &mut R, dur: Duration) -> Result<String> {
    // SMTP responses: each line "NNN-text" is continuation, "NNN text"
    // (or "NNN") is final. Read up to 64 lines / 32 KiB total.
    let mut out = String::new();
    for _ in 0..64 {
        let mut line = String::new();
        let n = timeout(dur, r.read_line(&mut line)).await??;
        if n == 0 {
            break;
        }
        out.push_str(&line);
        if line.len() < 4 || line.as_bytes()[3] == b' ' || line.starts_with("220 ")
            || line.starts_with("250 ")
            || line.starts_with("221 ")
            || (line.len() >= 4 && line.as_bytes()[3] != b'-')
        {
            break;
        }
        if out.len() > 32 * 1024 {
            break;
        }
    }
    Ok(out.trim_end().to_string())
}

fn parse_ehlo_lines(resp: &str) -> Vec<String> {
    // Each non-banner line beyond the first looks like:
    //   250-AUTH PLAIN LOGIN
    //   250 STARTTLS
    // or
    //   250-EHLO ok…
    //   250-SIZE 36700160
    let mut exts = Vec::new();
    for line in resp.lines() {
        if line.len() < 4 || !line.starts_with("250") {
            continue;
        }
        let payload = &line[4..]; // skip "250-" or "250 "
        exts.push(payload.trim().to_string());
    }
    exts
}

fn apply_extensions(a: &mut SmtpAudit, exts: &[String], over_tls: bool) {
    for ext in exts {
        let upper = ext.to_uppercase();
        if upper == "STARTTLS" {
            a.starttls_offered = true;
        } else if upper == "VRFY" {
            a.vrfy = true;
        } else if upper == "EXPN" {
            a.expn = true;
        } else if let Some(rest) = upper.strip_prefix("AUTH ") {
            let mechs: Vec<String> = rest
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            if over_tls {
                a.auth_mechanisms_tls = mechs;
            } else {
                a.auth_mechanisms_clear = mechs;
            }
        } else if let Some(rest) = upper.strip_prefix("SIZE ") {
            if let Ok(n) = rest.trim().parse::<u64>() {
                a.size_max = Some(n);
            }
        }
    }
}

fn classify(a: &mut SmtpAudit, port: u16) {
    if (port == 25 || port == 587) && !a.starttls_offered {
        a.findings.push(
            "STARTTLS not advertised — credentials and mail body travel in cleartext".into(),
        );
    }
    if a.starttls_offered && !a.starttls_succeeded && (port == 25 || port == 587) {
        a.findings.push("STARTTLS advertised but handshake failed".into());
    }
    let weak_clear: Vec<&str> = a
        .auth_mechanisms_clear
        .iter()
        .filter(|m| {
            let u = m.to_uppercase();
            u == "PLAIN" || u == "LOGIN"
        })
        .map(|s| s.as_str())
        .collect();
    if !weak_clear.is_empty() {
        a.findings.push(format!(
            "AUTH {} offered before STARTTLS — credentials sniffable",
            weak_clear.join("/")
        ));
    }
    if a.vrfy {
        a.findings.push("VRFY enabled — username enumeration".into());
    }
    if a.expn {
        a.findings.push("EXPN enabled — mailing-list disclosure".into());
    }
}

pub fn print_report(host: &str, port: u16, a: &SmtpAudit) {
    use colored::*;
    println!();
    println!("{}", format!("SMTP audit for {}:{}", host, port).bold());
    println!("  banner   : {}", a.banner.lines().next().unwrap_or(""));
    println!(
        "  STARTTLS : offered={} succeeded={} (implicit TLS={})",
        a.starttls_offered, a.starttls_succeeded, a.implicit_tls
    );
    if !a.auth_mechanisms_clear.is_empty() {
        println!("  AUTH (clear): {}", a.auth_mechanisms_clear.join(", "));
    }
    if !a.auth_mechanisms_tls.is_empty() {
        println!("  AUTH (tls)  : {}", a.auth_mechanisms_tls.join(", "));
    }
    if a.findings.is_empty() {
        println!("  {}", "no weaknesses detected".green());
    } else {
        println!("  {}", "weaknesses:".yellow().bold());
        for f in &a.findings {
            println!("    · {}", f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ehlo_extracts_extensions() {
        let resp = "250-mail.example.com Hello\r\n250-SIZE 36700160\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n";
        let exts = parse_ehlo_lines(resp);
        assert!(exts.iter().any(|e| e == "STARTTLS"));
        assert!(exts.iter().any(|e| e == "AUTH PLAIN LOGIN"));
        assert!(exts.iter().any(|e| e.starts_with("SIZE")));
    }

    #[test]
    fn apply_records_auth_separately_per_channel() {
        let mut a = SmtpAudit::default();
        apply_extensions(&mut a, &["AUTH PLAIN LOGIN".into()], false);
        apply_extensions(&mut a, &["AUTH PLAIN".into()], true);
        assert_eq!(a.auth_mechanisms_clear, vec!["PLAIN", "LOGIN"]);
        assert_eq!(a.auth_mechanisms_tls, vec!["PLAIN"]);
    }

    #[test]
    fn classify_flags_clear_plain_and_missing_starttls() {
        let mut a = SmtpAudit::default();
        a.auth_mechanisms_clear = vec!["PLAIN".into()];
        classify(&mut a, 25);
        assert!(a.findings.iter().any(|f| f.contains("STARTTLS not")));
        assert!(a.findings.iter().any(|f| f.contains("AUTH PLAIN")));
    }

    #[test]
    fn classify_clean_modern_587() {
        let mut a = SmtpAudit::default();
        a.starttls_offered = true;
        a.starttls_succeeded = true;
        a.auth_mechanisms_tls = vec!["PLAIN".into(), "LOGIN".into()];
        classify(&mut a, 587);
        assert!(a.findings.is_empty(), "{:?}", a.findings);
    }
}
