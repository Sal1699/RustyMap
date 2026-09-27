// @name: traefik-dashboard-exposed
// @description: Detect an exposed Traefik dashboard / API
// @category: proxy
// @severity: medium
// @tags: traefik, proxy, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8080 && p.port != 8081 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/api/rawdata`, 3000);
    if resp.status == 200 {
        let body = if type_of(resp.body) == "string" { resp.body } else { "" };
        if body.index_of("routers") >= 0 && body.index_of("services") >= 0 {
            findings.push(#{ severity: "medium", port: p.port, message: "Traefik API /api/rawdata exposed — reveals every route, service and backend" });
            continue;
        }
    }
    let dash = http_get(`http://${host.ip}:${p.port}/dashboard/`, 3000);
    let body = if type_of(dash.body) == "string" { dash.body } else { "" };
    if body.index_of("Traefik") >= 0 {
        findings.push(#{ severity: "low", port: p.port, message: "Traefik dashboard reachable — restrict it behind auth" });
    }
}
