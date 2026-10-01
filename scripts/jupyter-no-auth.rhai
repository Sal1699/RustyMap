// @name: jupyter-no-auth
// @description: Detect a Jupyter Notebook/Lab server with no token/password
// @category: devtools
// @severity: high
// @tags: jupyter, notebook, no-auth, rce
// @author: rustymap
// A Jupyter server with token/password auth answers /api/contents with 403;
// with auth disabled it returns 200 and the directory listing. An open
// Jupyter is effectively unauthenticated remote code execution.
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 8888 && p.port != 8889 && p.port != 8000 { continue; }
    // First confirm it is Jupyter at all.
    let ver = http_get(`http://${host.ip}:${p.port}/api`, 3000);
    let vbody = if type_of(ver.body) == "string" { ver.body } else { "" };
    if ver.status != 200 || vbody.index_of("\"version\"") < 0 { continue; }
    let contents = http_get(`http://${host.ip}:${p.port}/api/contents`, 3000);
    let cbody = if type_of(contents.body) == "string" { contents.body } else { "" };
    if contents.status == 200 && cbody.index_of("\"content\"") >= 0 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Jupyter server with NO authentication — browse/run code as the server user (RCE)"
        });
    } else {
        findings.push(#{
            severity: "info",
            port: p.port,
            message: "Jupyter server detected (token/password auth enabled)"
        });
    }
}
