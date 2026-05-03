//! TLS protocol-version enumeration — testssl.sh-light.
//!
//! For a given TLS port we probe each protocol version separately
//! (TLS 1.0 / 1.1 / 1.2 / 1.3) and record:
//!   - supported / not
//!   - cipher chosen by the server (when 1.2/1.3 — rustls handles
//!     these natively)
//!
//! TLS 1.0 and 1.1 are detected by hand-crafted ClientHello: rustls
//! refuses to negotiate them by design (which is correct — they're
//! deprecated and broken), but a server still happily replying with
//! a matching ServerHello version is a finding worth surfacing.
//!
//! Improvement over `testssl.sh`: built into the same scan, no
//! second tool, results land in the same JSON/HTML report next to
//! the cert info from `tls_probe`.

use anyhow::Result;
use rustls::{ClientConfig, ProtocolVersion};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsEnum {
    pub tls10: bool,
    pub tls11: bool,
    pub tls12: bool,
    pub tls13: bool,
    /// Cipher negotiated when each modern version handshakes.
    pub cipher_tls12: Option<String>,
    pub cipher_tls13: Option<String>,
}

impl TlsEnum {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.tls10 { parts.push("1.0".to_string()); }
        if self.tls11 { parts.push("1.1".to_string()); }
        if self.tls12 {
            parts.push(match &self.cipher_tls12 {
                Some(c) => format!("1.2({})", c),
                None => "1.2".into(),
            });
        }
        if self.tls13 {
            parts.push(match &self.cipher_tls13 {
                Some(c) => format!("1.3({})", c),
                None => "1.3".into(),
            });
        }
        if parts.is_empty() {
            "no TLS responded".to_string()
        } else {
            parts.join(" · ")
        }
    }

    /// Returns true when the server still speaks a deprecated
    /// protocol — surfaced as a finding.
    pub fn has_deprecated(&self) -> bool {
        self.tls10 || self.tls11
    }
}

fn build_config_for(protocol: ProtocolVersion) -> Arc<ClientConfig> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

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
    let versions: &[&rustls::SupportedProtocolVersion] = match protocol {
        ProtocolVersion::TLSv1_3 => &[&rustls::version::TLS13],
        _ => &[&rustls::version::TLS12],
    };
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("rustls protocol version")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Accept))
        .with_no_client_auth();
    Arc::new(cfg)
}

async fn probe_modern(
    ip: IpAddr,
    port: u16,
    sni: Option<&str>,
    proto: ProtocolVersion,
    dur: Duration,
) -> Option<String> {
    use rustls::pki_types::ServerName;
    let cfg = build_config_for(proto);
    let connector = TlsConnector::from(cfg);
    let addr = SocketAddr::new(ip, port);
    let tcp = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    let server_name = match sni {
        Some(h) => ServerName::try_from(h.to_string()).ok()?,
        None => ServerName::try_from(ip.to_string()).ok()?,
    };
    let tls = timeout(dur, connector.connect(server_name, tcp)).await.ok()?.ok()?;
    let (_, conn) = tls.get_ref();
    if conn.protocol_version() != Some(proto) {
        return None;
    }
    conn.negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
}

/// Hand-crafted ClientHello probe for TLS 1.0 / 1.1.
/// We don't need a working application-data channel — only to see if
/// the server replies with a matching ServerHello (handshake type 2)
/// at the requested protocol version.
async fn probe_legacy(ip: IpAddr, port: u16, ver: u16, dur: Duration) -> bool {
    // ClientHello structure (minimal):
    //   record-layer:  type(0x16) ver(2B) len(2B)
    //   handshake:     type(0x01) len(3B) ver(2B) random(32B)
    //                  session_id_len(0) cipher_suites_len(2B) ciphers
    //                  compression_methods_len(1) compression(0)
    //
    // We send 2 cipher suites that exist in TLS 1.0:
    //   0x002F = TLS_RSA_WITH_AES_128_CBC_SHA
    //   0x000A = TLS_RSA_WITH_3DES_EDE_CBC_SHA
    let v_hi = (ver >> 8) as u8;
    let v_lo = (ver & 0xff) as u8;
    let mut ch = Vec::with_capacity(80);
    // record header — placeholder length, fill after
    ch.extend_from_slice(&[0x16, v_hi, v_lo, 0, 0]);
    let body_off = ch.len();
    // handshake header — placeholder length
    ch.extend_from_slice(&[0x01, 0, 0, 0]);
    // client_version
    ch.extend_from_slice(&[v_hi, v_lo]);
    // 32 bytes of "random"
    ch.extend_from_slice(&[0xa5; 32]);
    // session id len
    ch.push(0);
    // cipher suites: 4 bytes (2 suites)
    ch.extend_from_slice(&[0x00, 0x04, 0x00, 0x2f, 0x00, 0x0a]);
    // compression methods len + null compression
    ch.extend_from_slice(&[0x01, 0x00]);
    // patch handshake length (24-bit big-endian)
    let hs_len = (ch.len() - body_off - 4) as u32;
    ch[body_off + 1] = ((hs_len >> 16) & 0xff) as u8;
    ch[body_off + 2] = ((hs_len >> 8) & 0xff) as u8;
    ch[body_off + 3] = (hs_len & 0xff) as u8;
    // patch record length
    let rec_len = (ch.len() - 5) as u16;
    ch[3] = (rec_len >> 8) as u8;
    ch[4] = (rec_len & 0xff) as u8;

    let addr = SocketAddr::new(ip, port);
    let mut s = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    if timeout(dur, s.write_all(&ch)).await.is_err() {
        return false;
    }
    // Need at least 11 bytes to read the ServerHello's negotiated
    // version (record header is 5 bytes; the inner negotiated
    // version lives at offset 9-10 — bytes after the handshake
    // header that follows). The record-layer version is unreliable
    // (many servers stamp 0x0301 there regardless of negotiated).
    let mut buf = [0u8; 16];
    let n = match timeout(dur, s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    n >= 11
        && buf[0] == 0x16        // handshake record
        && buf[5] == 0x02        // ServerHello
        && buf[9] == v_hi        // negotiated version matches the requested one
        && buf[10] == v_lo
}

pub async fn enumerate(ip: IpAddr, port: u16, sni: Option<&str>, dur: Duration) -> Result<TlsEnum> {
    let mut out = TlsEnum::default();
    out.tls10 = probe_legacy(ip, port, 0x0301, dur).await;
    out.tls11 = probe_legacy(ip, port, 0x0302, dur).await;
    out.cipher_tls12 = probe_modern(ip, port, sni, ProtocolVersion::TLSv1_2, dur).await;
    out.tls12 = out.cipher_tls12.is_some();
    out.cipher_tls13 = probe_modern(ip, port, sni, ProtocolVersion::TLSv1_3, dur).await;
    out.tls13 = out.cipher_tls13.is_some();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_includes_versions() {
        let e = TlsEnum {
            tls10: false,
            tls11: false,
            tls12: true,
            tls13: true,
            cipher_tls12: Some("AES_128_GCM".into()),
            cipher_tls13: Some("AES_256_GCM".into()),
        };
        let s = e.summary();
        assert!(s.contains("1.2(AES_128_GCM)"));
        assert!(s.contains("1.3(AES_256_GCM)"));
    }

    #[test]
    fn deprecated_detection() {
        let e = TlsEnum { tls10: true, tls13: true, ..Default::default() };
        assert!(e.has_deprecated());
        let f = TlsEnum { tls12: true, tls13: true, ..Default::default() };
        assert!(!f.has_deprecated());
    }

    #[test]
    fn empty_summary() {
        let e = TlsEnum::default();
        assert_eq!(e.summary(), "no TLS responded");
    }
}
