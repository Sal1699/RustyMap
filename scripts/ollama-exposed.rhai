// @name: ollama-exposed
// @description: Detect an exposed Ollama LLM server (unauth model pull/run)
// @category: ai
// @severity: high
// @tags: ai, llm, ollama, exposure
// @author: rustymap
for p in host.ports {
    if p.state != "open" { continue; }
    if p.port != 11434 && p.port != 8080 && p.port != 80 { continue; }
    let resp = http_get(`http://${host.ip}:${p.port}/`, 3000);
    if resp.status == 0 { continue; }
    let body = if type_of(resp.body) == "string" { resp.body } else { "" };
    if body.index_of("Ollama is running") >= 0 {
        findings.push(#{
            severity: "high",
            port: p.port,
            message: "Ollama LLM server exposed without auth — anyone can pull/run models and consume GPU/CPU"
        });
    }
}
