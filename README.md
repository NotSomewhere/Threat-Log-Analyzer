# Threat-Log-Analyzer (TLA)🛡️

**Defensive SSH/auth log analyzer** – schnell, klar und effektiv Logs analysieren, verdächtige Aktivitäten erkennen und Reports erzeugen.

🔍 Fokus liegt auf **Defensiv-Analyse**, nicht auf Angriffen.

---

## 📌 Features ✨
- ✅ Parser für **SSH/Auth-Logs** (z. B. `/var/log/auth.log`)
- 📅 Zeitfilter via `--since` (z. B. `24h`, `7d`, `30m`)
- 📊 Exporte in **HTML, CSV, JSON, JSONL**
- 📜 **YAML-Rules** für eigene Erkennungsregeln (`rules/*.yaml`)
- 🧪 Tests + CI-Workflows (pytest + GitHub Actions)
- 🧠 Modularer Aufbau für einfache Erweiterungen

---

## 🚀 Schnellstart
1. Repo klonen:
```bash
git clone https://github.com/NotSomewhere/Threat-Log-Analyzer.git
cd Threat-Log-Analyzer
```

1. Installation:
```bash
pip install -e .
```

1. Erstes Beispiel ausführen:
```bash
tla examples/auth.log.sample
```

---

## 📖 Nutzung
```bash
# Basis
 tla /var/log/auth.log --top 20

# Export als JSON
tla /var/log/auth.log --json > report.json

# Zeitfilter
tla /var/log/auth.log --since 24h

# HTML Report
tla /var/log/auth.log --html report.html

# CSV / JSONL Exporte
tla /var/log/auth.log --csv events.csv --jsonl events.jsonl

# Eigene Regeln
tla /var/log/auth.log --rules rules/default.yaml
```

---

## 📘 Regeln-Format
Regeln liegen in YAML und enthalten:

```yaml
- id: SSH_BRUTE_FORCE
  description: Viele fehlgeschlagene Login-Versuche
  severity: medium
  regex: "Failed password"
```

Wenn `--rules` nicht gesetzt ist, sucht das Tool zuerst im aktuellen Ordner nach `rules/default.yaml`, sonst nutzt es die mitgelieferten Defaults.

---

## 🗒️ Hinweise
- 🔒 Dieses Tool führt **keine Angriffe** aus – es ist rein defensiv/analytisch gedacht.
- 📂 Getestet mit Debian/Ubuntu `auth.log` – andere Formate können abweichen.
- 🎯 Genauigkeit hängt vom Log-Format ab.

---

## 🚧 Geplante Erweiterungen
- ✔️ Mehr Log-Formate (journald etc.)
- ✔️ IP-Enrichment (Geo/ASN) für tiefere Analysen
- ✔️ Visuelle Dashboards & Alerts
- ✔️ SIEM-Integration

---

## 📁 Projektlayout
```text
Threat-Log-Analyzer/
├── src/…
├── rules/
├── examples/
├── tests/
├── .github/workflows/
├── pyproject.toml
└── README.md
```

---

## 📜 Lizenz
MIT License

---

## ❤️ Über
Defensive SSH/auth log analyzer mit Berichten, Filtern und Regeln.

Made for GitHub. Built for defense.
