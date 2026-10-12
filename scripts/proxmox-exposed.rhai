// @name: proxmox-exposed
// @description: Proxmox VE web UI open
// @category: mgmt
// @severity: low
// @tags: mgmt, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8006 { continue; }
    findings.push(#{ severity: "low", port: 8006, message: "Proxmox VE web UI open" });
}
