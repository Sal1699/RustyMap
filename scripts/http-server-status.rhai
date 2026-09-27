// @name: http-server-status
// @description: Detect an exposed Apache mod_status /server-status page
// @category: http
// @severity: medium
// @tags: http, apache, info-leak
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/server-status`, 3000);
    if resp.status != 200 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Apache Server Status") >= 0 || body.index_of("Server uptime") >= 0 {
        findings.push(#{
            severity: "medium",
            port: p.port,
            message: "/server-status exposed — leaks client IPs, requested URLs and vhosts"
        });
    }
}
