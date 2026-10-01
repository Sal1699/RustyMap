// @name: rtsp-options
// @description: Probe RTSP OPTIONS to fingerprint streaming/camera servers
// @category: media
// @severity: low
// @tags: rtsp, camera, streaming, fingerprint
// @author: rustymap
// RTSP cameras and media servers answer an unauthenticated OPTIONS request
// with the server string and supported methods (Public: ...). An open RTSP
// endpoint frequently means a viewable camera stream behind weak creds.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 554 && p.port != 8554 && p.port != 10554 { continue; }
    let req = `OPTIONS rtsp://${host.ip}:${p.port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: rustymap\r\n\r\n`;
    let resp = tcp_send(host.ip, p.port, req, 3000);
    if resp.index_of("RTSP/1.0") < 0 { continue; }
    let server = regex_capture("(?i)server:\\s*([^\\r\\n]+)", resp);
    let methods = regex_capture("(?i)public:\\s*([^\\r\\n]+)", resp);
    let detail = if server != "" { server } else { "unknown server" };
    findings.push(#{
        severity: "low",
        port: p.port,
        message: `RTSP service exposed (${detail}); methods: ${methods}`
    });
}
