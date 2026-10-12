// @name: msrpc-epmap-exposed
// @description: MSRPC endpoint mapper open (enumeration surface)
// @category: smb
// @severity: medium
// @tags: smb, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 135 { continue; }
    findings.push(#{ severity: "medium", port: 135, message: "MSRPC endpoint mapper open (enumeration surface)" });
}
