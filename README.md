# threat-log-analyzer (tla) 🔍🛡️

**Analyze SSH/auth logs and summarize suspicious activity** — defensiv, klar, schnell.

## Features ✨
- ✅ SSH/auth Parser mit verdächtigen Mustern
- ✅ Zeitfilter via `--since` (z. B. `24h`, `7d`, `30m`)
- ✅ HTML, CSV, JSON, JSONL Export
- ✅ YAML‑Rules für eigene Detections (`rules/default.yaml`)
- ✅ Tests + CI (pytest + GitHub Actions)

## Quickstart 🚀
```bash
pip install -e .
```

```bash
tla examples/auth.log.sample
```

## Usage 🧪
```bash
tla /var/log/auth.log --top 20
tla /var/log/auth.log --json > report.json
```

## Power‑Options ⚡
```bash
# Time filter
tla /var/log/auth.log --since 24h

# HTML report
tla /var/log/auth.log --html report.html

# CSV / JSONL export
tla /var/log/auth.log --csv events.csv --jsonl events.jsonl

# Custom rules
tla /var/log/auth.log --rules rules/default.yaml
```

## Rules Format 🧩
`rules/default.yaml` ist eine Liste von Regeln. Wenn du `--rules` nicht angibst, nutzt das Tool zuerst `rules/default.yaml` im aktuellen Ordner, sonst die mitgelieferten Defaults.

```yaml
- id: SSH_BRUTE_FORCE
  description: Many failed password attempts
  severity: medium
  regex: "Failed password"
```

## Notes 📝
- Dieses Tool **führt keine Angriffe** aus.
- Fokus: Defensive / Education.
- Genauigkeit hängt vom Log‑Format ab (getestet mit Debian/Ubuntu `auth.log`).

## Next Steps 🔧
- Mehr Log‑Formate (journald, weitere sshd‑Varianten)
- IP‑Enrichment (Geo/ASN) für Blue‑Team‑Analysen

---

Made for GitHub. Built for defense. 🧠
