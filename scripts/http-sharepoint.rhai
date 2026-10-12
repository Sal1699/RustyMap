// @name: http-sharepoint
// @description: Microsoft SharePoint detected
// @category: http
// @severity: info
// @tags: http, http
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 8000 && p.port != 8888 && p.port != 9000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let base = `${scheme}://${host.ip}:${p.port}`;
    let nx = http_get(`${base}/rustymap_nx_9z8y7x7`, 2500);
    let nx200 = type_of(nx.body) == "string" && nx.status == 200;
    let nxlo = if type_of(nx.body) == "string" { nx.body.to_lower() } else { "" };
    let resp = http_get(`${base}/_layouts/15/start.aspx`, 3000);
    if type_of(resp.body) != "string" { continue; }
    let lo = resp.body.to_lower();
    if (resp.status == 200 || resp.status == 401 || resp.status == 302) && lo.contains("sharepoint") {
        if resp.status == 200 && nx200 && ("sharepoint" == "" || nxlo.contains("sharepoint")) { continue; }
        findings.push(#{ severity: "info", port: p.port, message: `Microsoft SharePoint detected (${base}/_layouts/15/start.aspx)` });
    }
}
