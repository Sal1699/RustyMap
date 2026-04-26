// Flag Microsoft SQL Server — frequent target of sa/blank or weak SA.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 1433 && p.port != 1434 { continue; }
    findings.push(#{
        severity: "high",
        port: p.port,
        message: "MSSQL reachable — verify the sa account has a strong password and that mixed-mode auth is intentional"
    });
}
