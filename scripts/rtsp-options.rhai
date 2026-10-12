// @name: rtsp-options
// @description: Probe RTSP OPTIONS to fingerprint streaming/camera servers
// @category: media
// @severity: low
// @tags: rtsp, camera, streaming, fingerprint
// @author: rustymap
// RTSP cameras and media servers answer an unauthenticated OPTIONS request
// with the server string and supported methods (Public: ...). An open RTSP
// endpoint frequently means a viewable camera stream behind weak creds.
//
// v0.87.1: build the request with REAL CRLF via normal-string escapes — a
// backtick template did not interpret \r\n, so the server never answered and
// the script silently did nothing (lab v0.87.0 BUG-4). Also match "RTSP/"
// broadly (1.0 and 2.0) and treat a 401 as a confirmed-but-auth'd camera.
let crlf = "\r\n";
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 554 && p.port != 8554 && p.port != 10554 && p.port != 8080 { continue; }
    // Skip 8080 unless the service looks like RTSP (shared port).
    if p.port == 8080 {
        let svc = p.service;
        let is_rtsp = type_of(svc) == "map" && type_of(svc.product) == "string"
            && svc.product.to_lower().contains("rtsp");
        if !is_rtsp { continue; }
    }
    let req = "OPTIONS rtsp://" + host.ip + "/ RTSP/1.0" + crlf
        + "CSeq: 1" + crlf + "User-Agent: rustymap" + crlf + crlf;
    let resp = tcp_send(host.ip, p.port, req, 3000);
    if type_of(resp) != "string" { continue; }
    if resp.to_upper().index_of("RTSP/") < 0 { continue; }
    let server = regex_capture("(?i)server:\\s*([^\\r\\n]+)", resp);
    let methods = regex_capture("(?i)public:\\s*([^\\r\\n]+)", resp);
    let detail = if server != "" { server } else { "RTSP server" };
    let auth = if resp.contains("401") { " (401 — auth required)" } else { "" };
    findings.push(#{
        severity: "low",
        port: p.port,
        message: `RTSP service exposed${auth}: ${detail}; methods: ${methods}`
    });
}
