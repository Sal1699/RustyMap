// Flag Kubernetes API server / kubelet / etcd reachable.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port == 6443 || p.port == 8443 {
        let svc = p.service;
        let banner = if type_of(svc) == "map" {
            let b = svc.banner;
            if type_of(b) == "string" { b.to_lower() } else { "" }
        } else { "" };
        if banner.contains("kube") || banner.contains("apiserver") {
            findings.push(#{
                severity: "high",
                port: p.port,
                message: "Kubernetes API server reachable — verify RBAC + token auth"
            });
        }
    }
    if p.port == 10250 {
        findings.push(#{
            severity: "critical",
            port: 10250,
            message: "kubelet API on 10250 — without --anonymous-auth=false this exposes container exec"
        });
    }
    if p.port == 2379 || p.port == 2380 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "etcd cluster port — full k8s state read/write if no client cert auth"
        });
    }
}
