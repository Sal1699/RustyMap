// Flag NFS reachable from the network. Default exports often have no_root_squash.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 2049 && p.port != 111 { continue; }
    findings.push(#{
        severity: "medium",
        port: p.port,
        message: "NFS / RPC portmap reachable — `showmount -e <host>` enumerates exports; verify no_root_squash is off"
    });
}
