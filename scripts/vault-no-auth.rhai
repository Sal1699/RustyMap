// Active probe: HashiCorp Vault /v1/sys/health. An unsealed Vault with
// no authentication mechanism enforcing a check on the health endpoint
// can still leak version info; combined with `initialized:false` it
// signals a fresh, attacker-claimable instance.
// @name: vault-no-auth
// @description: Detect HashiCorp Vault instances that are uninitialized or unsealed without auth
// @category: vuln
// @severity: critical
// @tags: vault secrets hashicorp
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8200 { continue; }
    let url = `http://${host.ip}:${p.port}/v1/sys/health`;
    let resp = http_get(url, 3000);
    // 200=initialized+unsealed+active, 501=uninit, 503=sealed, 429=standby
    if resp.body == "" { continue; }
    let ver = regex_capture(`"version":"([^"]+)"`, resp.body);
    if regex_match(`"initialized":\\s*false`, resp.body) {
        findings.push(#{
            severity: "critical",
            port: p.port,
            message: `Vault ${ver} is uninitialized — anyone can take over by calling /v1/sys/init`
        });
        continue;
    }
    if resp.status == 200 && regex_match(`"sealed":\\s*false`, resp.body) {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: `Vault ${ver} unsealed + reachable — verify auth methods are enforced`
        });
    }
}
