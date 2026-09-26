// @name: sip-options
// @description: Send a SIP OPTIONS request (5060/udp) and name the UA/server
// @category: udp
// @severity: info
// @tags: sip, voip, recon
// @author: rustymap
// NSE-equivalent of sip-methods/sip-enum: a responding SIP endpoint returns
// Server/User-Agent and its Allow list of methods.
let req = "OPTIONS sip:100@" + host.ip + " SIP/2.0\r\n"
    + "Via: SIP/2.0/UDP rustymap:5060;branch=z9hG4bKrm\r\n"
    + "From: <sip:rustymap@rustymap>;tag=rm\r\n"
    + "To: <sip:100@" + host.ip + ">\r\n"
    + "Call-ID: rustymap-scan\r\n"
    + "CSeq: 1 OPTIONS\r\n"
    + "Max-Forwards: 70\r\n"
    + "Content-Length: 0\r\n\r\n";
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5060 && p.port != 5061 { continue; }
    let resp = udp_send(host.ip, p.port, req, 2500);
    if resp.index_of("SIP/2.0") < 0 { continue; }
    let srv = regex_capture("(?i)(?:Server|User-Agent):\\s*([^\\r\\n]+)", resp);
    let allow = regex_capture("(?i)Allow:\\s*([^\\r\\n]+)", resp);
    findings.push(#{
        severity: "info",
        port: p.port,
        message: if srv != "" { `SIP server: ${srv.trim()}` } else { "SIP endpoint responded to OPTIONS" }
    });
    if allow != "" {
        findings.push(#{ severity: "info", port: p.port, message: `SIP methods: ${allow.trim()}` });
    }
}
