// Flag MQTT broker — many IoT deployments leave allow_anonymous=true.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1883 && p.port != 8883 && p.port != 8083 { continue; }
    let sev = if p.port == 8883 { "low" } else { "high" };
    let where = if p.port == 8883 { " (TLS)" } else { "" };
    findings.push(#{
        severity: sev,
        port: p.port,
        message: `MQTT broker reachable${where} — verify allow_anonymous=false and enforce per-topic ACLs`
    });
}
