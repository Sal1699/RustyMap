// @name: telnet-exposed
// @description: Flag a reachable Telnet service (cleartext remote login)
// @category: cleartext
// @severity: medium
// @tags: telnet, cleartext, legacy
// @author: rustymap
// Telnet carries credentials and the whole session in clear text. Any
// reachable Telnet port is a finding on its own; the banner (when the
// server sends a printable prompt rather than only IAC negotiation) often
// names the device, which is useful for IoT/router triage.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 23 && p.port != 2323 && p.port != 992 { continue; }
    let banner = tcp_send(host.ip, p.port, "", 2500);
    let prompt = regex_capture("(?i)([A-Za-z0-9._ -]*(login|username|password)[^\\r\\n]*)", banner);
    let msg = if prompt != "" {
        `Telnet exposed (cleartext login) — prompt: ${prompt}`
    } else {
        "Telnet exposed — credentials and session travel in clear text"
    };
    findings.push(#{ severity: "medium", port: p.port, message: msg });
}
