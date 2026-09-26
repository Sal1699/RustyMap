// @name: http-security-txt
// @description: Detect /.well-known/security.txt and surface its contact
// @category: http
// @severity: info
// @tags: http, recon, disclosure-policy
// @author: rustymap
// RFC 9116: presence signals a vuln-disclosure process; the Contact line
// is useful recon and confirms the org runs a security program.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8443 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/.well-known/security.txt`, 3000);
    if resp.status != 200 { continue; }
    if type_of(resp.body) != "string" { continue; }
    let contact = regex_capture("(?i)Contact:\\s*([^\\r\\n]+)", resp.body);
    let msg = if contact != "" {
        `security.txt present — Contact: ${contact.trim()}`
    } else {
        "security.txt present (RFC 9116 disclosure policy)"
    };
    findings.push(#{ severity: "info", port: p.port, message: msg });
}
