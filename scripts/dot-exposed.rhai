// @name: dot-exposed
// @description: DNS-over-TLS (853) open
// @category: dns
// @severity: info
// @tags: dns, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 853 { continue; }
    findings.push(#{ severity: "info", port: 853, message: "DNS-over-TLS (853) open" });
}
