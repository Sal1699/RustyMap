// @name: coap-exposed
// @description: CoAP open (IoT; amplification)
// @category: iot
// @severity: low
// @tags: iot, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 5683 { continue; }
    findings.push(#{ severity: "low", port: 5683, message: "CoAP open (IoT; amplification)" });
}
