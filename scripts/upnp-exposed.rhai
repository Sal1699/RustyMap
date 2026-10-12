// @name: upnp-exposed
// @description: SSDP/UPnP open (device/amplification)
// @category: iot
// @severity: low
// @tags: iot, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1900 { continue; }
    findings.push(#{ severity: "low", port: 1900, message: "SSDP/UPnP open (device/amplification)" });
}
