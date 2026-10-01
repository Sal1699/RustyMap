// @name: http-trace-enabled
// @description: Detect the HTTP TRACE method (Cross-Site Tracing)
// @category: http
// @severity: low
// @tags: http, trace, xst, misconfiguration
// @author: rustymap
// A server that honours TRACE echoes the request back, which can be abused
// for Cross-Site Tracing to read otherwise-protected headers/cookies. Sent
// over the raw socket since http_get only issues GET. Cleartext ports only.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 8080 && p.port != 8000 && p.port != 8888 { continue; }
    let req = `TRACE / HTTP/1.1\r\nHost: ${host.ip}\r\nX-Rustymap: probe\r\nConnection: close\r\n\r\n`;
    let resp = tcp_send(host.ip, p.port, req, 3000);
    if resp.index_of("HTTP/1.") < 0 { continue; }
    let status = regex_capture("HTTP/1\\.[01]\\s+([0-9]{3})", resp);
    if status != "200" { continue; }
    // The method is live only if the response body echoes our request line.
    if resp.index_of("TRACE /") >= 0 && resp.to_lower().index_of("x-rustymap") >= 0 {
        findings.push(#{
            severity: "low",
            port: p.port,
            message: "HTTP TRACE method enabled — vulnerable to Cross-Site Tracing (XST); disable TRACE"
        });
    }
}
