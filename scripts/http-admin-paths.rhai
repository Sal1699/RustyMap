// Flag exposed admin/setup pages on HTTP based on title or Server hint.
// Doesn't fetch URLs (no HTTP client in scripts) — only reasons over what
// vendor_probe already extracted into device.hints.
let admin_titles = ["admin", "login", "setup", "phpmyadmin", "manager", "wizard", "dashboard"];
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 80 && p.port != 8080 && p.port != 8443 && p.port != 443 && p.port != 8000 && p.port != 81 { continue; }
    let svc = p.service;
    if type_of(svc) != "map" { continue; }
    let banner = svc.banner;
    if type_of(banner) != "string" { continue; }
    let lo = banner.to_lower();
    for t in admin_titles {
        if lo.contains(t) {
            findings.push(#{
                severity: "high",
                port: p.port,
                message: `HTTP banner exposes administrative surface: '${t}' — restrict access`
            });
            break;
        }
    }
}
