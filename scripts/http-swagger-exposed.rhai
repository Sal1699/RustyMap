// @name: http-swagger-exposed
// @description: Detect an exposed Swagger UI / OpenAPI spec
// @category: http
// @severity: low
// @tags: http, api, swagger, openapi
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 3000 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let paths = ["/swagger-ui/index.html", "/swagger/index.html", "/openapi.json", "/v3/api-docs"];
    for path in paths {
        let resp = http_get(`${scheme}://${host.ip}:${p.port}${path}`, 3000);
        if resp.status != 200 { continue; }
        let body = if type_of(resp.body) == "string" { resp.body } else { "" };
        if body.index_of("swagger") >= 0 || body.index_of("openapi") >= 0 || body.index_of("Swagger UI") >= 0 {
            findings.push(#{
                severity: "low",
                port: p.port,
                message: `API documentation exposed at ${path} — maps the full attack surface`
            });
            break;
        }
    }
}
