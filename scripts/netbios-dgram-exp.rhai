// @name: netbios-dgram-exp
// @description: NetBIOS datagram service open
// @category: smb
// @severity: low
// @tags: smb, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 138 { continue; }
    findings.push(#{ severity: "low", port: 138, message: "NetBIOS datagram service open" });
}
