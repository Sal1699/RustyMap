// Flag rsync daemon — anonymous module enumeration possible by default.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 873 { continue; }
    findings.push(#{
        severity: "medium",
        port: 873,
        message: "rsync daemon — `rsync host::` lists modules; verify hosts allow + auth users in rsyncd.conf"
    });
}
