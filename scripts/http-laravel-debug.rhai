// @name: http-laravel-debug
// @description: Detect Laravel/PHP debug mode leaking stack traces & env
// @category: http
// @severity: high
// @tags: http, laravel, debug, info-leak
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    // A bogus path often triggers the debug error page when APP_DEBUG=true.
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/rustymap-404-probe`, 3000);
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Whoops") >= 0 && body.index_of("Laravel") >= 0 {
        findings.push(#{ severity: "high", port: p.port, message: "Laravel debug mode ON (Whoops! page) — leaks source, env vars and DB creds. Set APP_DEBUG=false" });
    } else if body.index_of("Stack trace:") >= 0 && body.index_of("vendor/") >= 0 {
        findings.push(#{ severity: "medium", port: p.port, message: "PHP stack trace leaked on error — disable display_errors in production" });
    }
}
