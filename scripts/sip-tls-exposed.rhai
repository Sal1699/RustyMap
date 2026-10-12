// @name: sip-tls-exposed
// @description: SIP-TLS (5061) open
// @category: voip
// @severity: info
// @tags: voip, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5061 { continue; }
    findings.push(#{ severity: "info", port: 5061, message: "SIP-TLS (5061) open" });
}
