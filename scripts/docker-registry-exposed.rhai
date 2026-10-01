// @name: docker-registry-exposed
// @description: Detect an open Docker Registry v2 API (image catalog readable)
// @category: devops
// @severity: high
// @tags: docker, registry, no-auth, exposure
// @author: rustymap
// A Docker Registry answers /v2/ with 200 (or an empty JSON) when it speaks
// the v2 API. If /v2/_catalog also returns 200 the repository list — and the
// images behind it, frequently with embedded secrets — is readable by anyone.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5000 && p.port != 443 && p.port != 5001 { continue; }
    let scheme = if p.port == 443 { "https" } else { "http" };
    let base = http_get(`${scheme}://${host.ip}:${p.port}/v2/`, 3000);
    let bhdr = if type_of(base.headers) == "string" { base.headers.to_lower() } else { "" };
    let is_registry = base.status == 200 || base.status == 401 || bhdr.index_of("docker-distribution-api-version") >= 0;
    if !is_registry { continue; }
    let cat = http_get(`${scheme}://${host.ip}:${p.port}/v2/_catalog`, 3000);
    let cbody = if type_of(cat.body) == "string" { cat.body } else { "" };
    if cat.status == 200 && cbody.index_of("repositories") >= 0 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Docker Registry v2 catalog readable without auth — image repositories are enumerable"
        });
    } else if base.status == 401 {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "Docker Registry v2 detected (authentication required)"
        });
    }
}
