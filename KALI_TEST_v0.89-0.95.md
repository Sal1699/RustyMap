# RustyMap — Kali Test Roadmap: Fasi 31→37 (v0.89.0 → v0.95.0)

Un **unico giro di validazione** per tutte le fasi feature rimanenti. Ogni fase
è una release separata ma si testa insieme. Dove serve `root` è indicato; serve
`hyperfine` per i bench. Riferimenti reali del tuo lab: ROUTER=.1, SERVER=.31,
CAM=.226, NET=192.168.1.0/24.

## 0. Update all'ultima
```sh
cd ~/RustyMap && git fetch origin --tags && git checkout v0.95.0 && cargo build --release
sudo install -m 0755 target/release/rustymap /usr/local/bin/rustymap
rustymap --version   # → rustymap 0.95.0
RM=rustymap ; ROUTER=192.168.1.1 ; SERVER=192.168.1.31 ; NET=192.168.1.0/24
```

---

## Fase 31 — Congestion control (v0.89.0)  [root]
Il test che mancava: la cwnd deve stabilizzare il `--fast-engine` sul full-port
e recuperare open sotto rate-limit.

| # | Comando | Atteso |
|---|---------|--------|
| 31.1 | `hyperfine -w1 -r5 "sudo $RM --sS --fast-engine -p 1-65535 $SERVER" "sudo $RM --sS --legacy-engine -p 1-65535 $SERVER" "sudo nmap -sS -p- -n $SERVER"` | fast **stabile** (σ bassa, niente 12–48s); nmap come controllo |
| 31.2 | `for i in 1 2 3; do sudo $RM --sS --fast-engine -p 1-1000 $ROUTER \| grep -c open; done` vs `--legacy-engine` e `nmap` | fast recupera **≥** open del legacy, verso nmap |
| 31.3 | `time sudo $RM --sS --fast-engine --max-rate 1000 -p 1-65535 $SERVER` | durata ≳ porte/1000 (tetto rispettato) |
| 31.4 | `sudo $RM --sS --fast-engine --min-rate 5000 -p 1-65535 $ROUTER` | non collassa a cwnd minima |

**Decisione:** se 31.1 stabile + 31.2 recupera → `--fast-engine` candidato a
ri-promozione a default (bench same-run).

---

## Fase 32 — -sV dietro TLS (v0.90.0)
| # | Comando | Atteso |
|---|---------|--------|
| 32.1 | `$RM --sV --version-all $SERVER -p 443,8443` | il servizio DIETRO TLS identificato (es. `lighttpd 1.4.x`, non `ssl/https`) |
| 32.2 | `$RM --sV --version-all --tls-scan $ROUTER -p 443` | prodotto/versione + cert insieme |
| 32.3 | (se hai nmap-service-probes) `$RM --sV --nmap-service-probes /usr/share/nmap/nmap-service-probes $SERVER` | banner `match rules loaded`; match extra |

---

## Fase 33 — Web-scan moderno (v0.91.0)
| # | Comando | Atteso |
|---|---------|--------|
| 33.1 | `$RM --web-scan $ROUTER -p 80,443` | riga `Tech:` (server/framework/lib), `CSP:` issues, `Endpoints:`, eventuali `secrets:` |
| 33.2 | `$RM --web-scan <un'app reale> ` | tech-fp coerente (WordPress/React/nginx…), endpoint estratti da JS/HTML |
| 33.3 | verifica no-FP su router catch-all | `Tech:` ragionevole, niente secret/endpoint falsi |

---

## Fase 34 — Mobile (v0.92.0)
| # | Comando | Atteso |
|---|---------|--------|
| 34.1 | `$RM --mobile-discover <IP telefono Android con ADB WiFi>` | `OS: Android`, `tcp/5555 ADB debug bridge open`, exit 1 |
| 34.2 | `$RM --mobile-discover <IP iPhone>` | lockdownd 62078 se raggiungibile, altrimenti suggerisce `--iot-discover` |
| 34.3 | `$RM --apk-scan <app.apk>` | riga `trackers / SDKs:` con AdMob/Firebase/Facebook ecc. |

---

## Fase 35 — Evasione (v0.93.0)
| # | Comando | Atteso |
|---|---------|--------|
| 35.1 | `$RM --ja3 chrome` / `--ja3 all` | JA3 string + hash MD5 + JA4 per browser |
| 35.2 | `sudo $RM --sS --evasion ghost --frag-random-order -F $SERVER` [root] | scan ok; con `--trace-raw`/tcpdump i frammenti escono in ordine casuale |
| 35.3 | `sudo tcpdump -i <if> 'host $SERVER'` durante 35.2 | frammenti IP con offset non monotòni |

---

## Fase 36 — SARIF (v0.94.0)
| # | Comando | Atteso |
|---|---------|--------|
| 36.1 | `$RM --sV --sarif scan.sarif $SERVER` poi `jq .version scan.sarif` | `"2.1.0"`; `jq '.runs[0].results\|length'` > 0 |
| 36.2 | carica `scan.sarif` su GitHub code-scanning (o `sarif-tools`) | risultati renderizzati, porte come note con categoria |

---

## Fase 37 — Speed + DNS cache (v0.95.0)
| # | Comando | Atteso |
|---|---------|--------|
| 37.1 | `time sudo $RM -sL -R $NET` (reverse DNS su /24) | completa; i repeat di IP non ri-risolvono (cache) |
| 37.2 | `cd ~/RustyMap && cargo bench --bench lab_compare` | micro-baseline girano; gate >10% documentato in PERFORMANCE.md |
| 37.3 | (facoltativo, root) `cargo flamegraph --bin rustymap -- --sS -p 1-65535 $SERVER` | profilo hot-path per i prossimi tuning |

---

## Done criteria
Un unico `VALIDATION_0.95.md` con una riga per fase (31→37) + aggiornamento
`LAB_VALIDATION.md`. Bug → li raccolgo e li fixo in un giro di patch. Se tutto
verde: si valuta il **taglio v1.0 (Fase 26, portfolio polish)** — che parte solo
col tuo ok.
