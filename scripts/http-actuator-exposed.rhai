// @name: http-actuator-exposed
// @description: Detect exposed Spring Boot Actuator endpoints
// @category: http
// @severity: high
// @tags: http, spring, actuator, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 443 && p.port != 8080 && p.port != 8443 && p.port != 9090 { continue; }
    let scheme = if p.port == 443 || p.port == 8443 { "https" } else { "http" };
    let env = http_get(`${scheme}://${host.ip}:${p.port}/actuator/env`, 3000);
    if env.status == 200 {
        let body = if type_of(env.body) == "string" { env.body } else { "" };
        if body.index_of("propertySources") >= 0 || body.index_of("systemProperties") >= 0 {
            findings.push(#{
                severity: "high",
                port: p.port,
                message: "/actuator/env exposed — leaks environment/config (often DB creds, tokens)"
            });
            continue;
        }
    }
    let health = http_get(`${scheme}://${host.ip}:${p.port}/actuator/health`, 3000);
    if health.status == 200 {
        let hb = if type_of(health.body) == "string" { health.body } else { "" };
        if hb.index_of("\"status\"") >= 0 && hb.index_of("UP") >= 0 {
            findings.push(#{
                severity: "low",
                port: p.port,
                message: "Spring Boot Actuator reachable (/actuator/health) — verify sensitive endpoints are locked"
            });
        }
    }
}
