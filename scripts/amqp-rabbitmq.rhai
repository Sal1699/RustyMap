// @name: amqp-rabbitmq
// @description: RabbitMQ AMQP broker
// @category: misc
// @severity: info
// @tags: misc, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5672 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("rabbit") {
        findings.push(#{ severity: "info", port: 5672, message: `RabbitMQ AMQP broker: ${b.trim()}` });
    }
}
