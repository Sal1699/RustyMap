// Flag RabbitMQ management UI (15672/15671) — guest:guest by default.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 15672 && p.port != 15671 && p.port != 5672 && p.port != 5671 { continue; }
    let sev = if p.port == 15672 { "high" } else { "medium" };
    let what = if p.port == 15672 || p.port == 15671 {
        "RabbitMQ management UI"
    } else {
        "RabbitMQ AMQP"
    };
    findings.push(#{
        severity: sev,
        port: p.port,
        message: `${what} reachable — change the default guest:guest credentials`
    });
}
