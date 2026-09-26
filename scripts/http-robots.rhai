// @name: http-robots
// @description: Fetch /robots.txt and surface Disallow paths (recon map)
// @category: http
// @severity: info
// @tags: http, recon
// @author: rustymap
// NSE-equivalent of http-robots.txt: the disallowed paths often point
// straight at admin panels, backups and staging areas.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443
        && p.port != 8000 && p.port != 8888 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let resp = http_get(`${scheme}://${host.ip}:${p.port}/robots.txt`, 3000);
    if resp.status != 200 { continue; }
    if type_of(resp.body) != "string" { continue; }
    let paths = regex_find_all("(?i)Disallow:\\s*(\\S+)", resp.body);
    if len(paths) == 0 { continue; }
    let n = len(paths);
    let shown = if n > 12 { 12 } else { n };
    let list = "";
    for i in 0..shown { list += paths[i] + " "; }
    findings.push(#{
        severity: "info",
        port: p.port,
        message: `robots.txt lists ${n} Disallow path(s): ${list.trim()}`
    });
}
