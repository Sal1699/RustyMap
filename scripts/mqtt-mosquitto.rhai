// @name: mqtt-mosquitto
// @description: Eclipse Mosquitto MQTT broker
// @category: iot
// @severity: info
// @tags: iot, banner, version
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1883 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let b = svc.banner;
    if type_of(b) != "string" { continue; }
    if b.to_lower().contains("mosquitto") {
        findings.push(#{ severity: "info", port: 1883, message: `Eclipse Mosquitto MQTT broker: ${b.trim()}` });
    }
}
