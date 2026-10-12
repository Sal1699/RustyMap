// @name: http-jboss-console
// @description: JBoss JMX console reachable
// @category: http
// @severity: medium
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
    let resp = http_get(`${base}/jmx-console/`, 3000);
    if type_of(resp.body) != "string" { continue; }
    let lo = resp.body.to_lower();
    if (resp.status == 200 || resp.status == 401 || resp.status == 302) && lo.contains("jboss") {
        if resp.status == 200 && nx200 && ("jboss" == "" || nxlo.contains("jboss")) { continue; }
        findings.push(#{ severity: "medium", port: p.port, message: `JBoss JMX console reachable (${base}/jmx-console/)` });
    }
}
