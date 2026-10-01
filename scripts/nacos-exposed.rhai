// @name: nacos-exposed
// @description: Detect an exposed Alibaba Nacos console/config server
// @category: devops
// @severity: medium
// @tags: nacos, config, service-discovery, exposure
// @author: rustymap
// Nacos (service discovery + config center) exposes its console on 8848.
// Several versions allow an authentication bypass (CVE-2021-29441) and ship
// nacos/nacos defaults, giving access to every application's config secrets.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8848 && p.port != 9848 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/nacos/`, 3000);
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if resp.status != 200 || body.to_lower().index_of("nacos") < 0 { continue; }
    let ver = http_get(`http://${host.ip}:${p.port}/nacos/v1/console/server/state`, 3000);
    let vbody = if type_of(ver.body) == "string" { ver.body } else { "" };
    let version = regex_capture("\"version\"\\s*:\\s*\"([^\"]+)\"", vbody);
    let msg = if version != "" {
        `Nacos console exposed (version ${version}) — check CVE-2021-29441 auth bypass and default nacos/nacos`
    } else {
        "Nacos console exposed — check for default credentials and auth-bypass CVEs"
    };
    findings.push(#{ severity: "medium", port: p.port, message: msg });
}
