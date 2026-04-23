//! Active TLS handshake probe.
//!
//! Connects to a TLS service, completes the handshake (without verifying the
//! cert chain — we are scanning, not consuming), and parses the leaf
//! certificate to surface subject / issuer / SANs / validity / signature
//! algorithm. The negotiated protocol version is also reported, so callers
//! can flag TLS 1.0/1.1 endpoints.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsInfo {
    pub negotiated: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub san: Vec<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub signature_alg: Option<String>,
    pub key_bits: Option<u32>,
    pub self_signed: bool,
    pub expired: bool,
}

impl TlsInfo {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = &self.negotiated {
            parts.push(p.clone());
        }
        if let Some(s) = &self.subject {
            parts.push(s.clone());
        }
        if self.expired {
            parts.push("EXPIRED".into());
        }
        if self.self_signed {
            parts.push("self-signed".into());
        }
        parts.join(" ")
    }
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn build_config() -> Arc<ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    Arc::new(cfg)
}

fn parse_leaf(der: &[u8]) -> TlsInfo {
    let mut info = TlsInfo::default();
    if let Ok((_, cert)) = X509Certificate::from_der(der) {
        info.subject = Some(cert.subject().to_string());
        info.issuer = Some(cert.issuer().to_string());
        info.self_signed = cert.subject() == cert.issuer();
        info.signature_alg = Some(format!("{:?}", cert.signature_algorithm.algorithm));

        let nb = cert.validity().not_before;
        let na = cert.validity().not_after;
        info.not_before = Some(nb.to_string());
        info.not_after = Some(na.to_string());
        if let Ok(now) = ASN1Time::from_timestamp(chrono::Utc::now().timestamp()) {
            info.expired = na < now;
        }

        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for n in &san.general_names {
                    if let GeneralName::DNSName(d) = n {
                        info.san.push(d.to_string());
                    }
                }
            }
        }

        if let Ok(spki) = cert.public_key().parsed() {
            info.key_bits = match spki {
                PublicKey::RSA(rsa) => Some((rsa.key_size() * 8) as u32),
                PublicKey::EC(ec) => Some((ec.key_size() * 8) as u32),
                _ => None,
            };
        }
    }
    info
}

fn version_label(v: rustls::ProtocolVersion) -> &'static str {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3",
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2",
        rustls::ProtocolVersion::TLSv1_1 => "TLS 1.1 (deprecated)",
        rustls::ProtocolVersion::TLSv1_0 => "TLS 1.0 (deprecated)",
        _ => "TLS unknown",
    }
}

pub async fn probe(
    ip: IpAddr,
    port: u16,
    dur: Duration,
    sni: Option<&str>,
) -> Option<TlsInfo> {
    let cfg = build_config();
    let connector = TlsConnector::from(cfg);

    let addr = SocketAddr::new(ip, port);
    let tcp = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;

    // Real hostname when known, else IP literal (rustls accepts both).
    let server_name = match sni {
        Some(h) => ServerName::try_from(h.to_string()).ok()?,
        None => ServerName::try_from(ip.to_string()).ok()?,
    };
    let tls = timeout(dur, connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;

    let (_, conn) = tls.get_ref();
    let mut info = conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| parse_leaf(leaf.as_ref()))
        .unwrap_or_default();
    info.negotiated = conn.protocol_version().map(|v| version_label(v).to_string());
    Some(info)
}

const TLS_PORTS: &[u16] = &[443, 465, 636, 853, 993, 995, 5061, 8443, 9443];

pub fn likely_tls(port: u16) -> bool {
    TLS_PORTS.contains(&port)
}
