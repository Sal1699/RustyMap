// @name: http-phpinfo
// @description: Find an exposed phpinfo() page leaking server internals
// @category: http
// @severity: medium
// @tags: http, php, phpinfo, info-leak
// @author: rustymap
// A reachable phpinfo() page discloses the full PHP configuration: absolute
// paths, loaded modules, environment variables (often with secrets) and the
// exact PHP build for targeting known CVEs.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8000 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    for path in ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php"] {
        let resp = http_get(`${scheme}://${host.ip}:${p.port}${path}`, 3000);
        if resp.status != 200 { continue; }
        let body = if type_of(resp.body) == "string" { resp.body } else { "" };
        if body.index_of("phpinfo()") >= 0 || regex_capture("(PHP Version\\s*[0-9]+\\.[0-9]+)", body) != "" {
            let ver = regex_capture("PHP Version\\s*([0-9][0-9A-Za-z.]+)", body);
            findings.push(#{
                severity: "medium",
                port: p.port,
                message: `phpinfo() exposed at ${path} (PHP ${ver}) — leaks paths, modules and environment`
            });
            break;
        }
    }
}
