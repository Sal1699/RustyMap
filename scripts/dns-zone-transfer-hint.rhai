// Flag DNS servers exposing AXFR — full zone listing if reachable.
// We can't actually do AXFR from the script (no socket access in rhai),
// so this just surfaces the candidate so the operator can `dig AXFR`.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 53 { continue; }
    findings.push(#{
        severity: "medium",
        port: 53,
        message: "DNS reachable — try `dig AXFR @<host> <zone>` (zone transfer leaks every record if allowed)"
    });
}
