// @name: http-server-tech
// @description: Report Server / X-Powered-By tech from HTTP headers
// @category: http
// @severity: info
// @tags: http, recon, fingerprint
// @author: rustymap
// NSE-equivalent of http-headers: names the web stack (and version)
// straight from the response headers.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443
        && p.port != 8000 && p.port != 8888 && p.port != 3000 && p.port != 5000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    if type_of(resp.headers) != "string" { continue; }
    let server = regex_capture("(?i)server:\\s*([^\\r\\n]+)", resp.headers);
    let powered = regex_capture("(?i)x-powered-by:\\s*([^\\r\\n]+)", resp.headers);
    if server != "" {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: `Server: ${server.trim()}`
        });
    }
    if powered != "" {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: `X-Powered-By: ${powered.trim()}`
        });
    }
}
