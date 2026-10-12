// @name: niagara-fox-exposed
// @description: Niagara Fox open (building control)
// @category: ics
// @severity: medium
// @tags: ics, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1911 { continue; }
    findings.push(#{ severity: "medium", port: 1911, message: "Niagara Fox open (building control)" });
}
