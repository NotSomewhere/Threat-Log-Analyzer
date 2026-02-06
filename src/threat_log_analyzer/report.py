from collections import Counter
from datetime import datetime
from typing import Dict, List, Any, Iterable

from .parsers import AuthEvent


def summarize(events: List[AuthEvent], top_n: int = 10, rule_hits: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    by_kind = Counter(e.kind for e in events)
    ips_failed = Counter(e.ip for e in events if e.kind in ("failed_password", "invalid_user"))
    users_failed = Counter((e.user or "UNKNOWN") for e in events if e.kind in ("failed_password", "invalid_user"))
    ips_success = Counter(e.ip for e in events if e.kind == "accepted_password")

    # Simple 'suspicion score': many failures => higher
    suspicious = [
        {"ip": ip, "fail_count": c, "score": min(100, c * 5)}
        for ip, c in ips_failed.most_common(top_n)
    ]

    ts_values = [e.ts for e in events if e.ts]
    first_ts = min(ts_values) if ts_values else None
    last_ts = max(ts_values) if ts_values else None

    return {
        "total_events": len(events),
        "counts": dict(by_kind),
        "top_failed_ips": ips_failed.most_common(top_n),
        "top_failed_users": users_failed.most_common(top_n),
        "top_success_ips": ips_success.most_common(top_n),
        "suspicious": suspicious,
        "time_range": {
            "first": first_ts.isoformat(sep=" ") if first_ts else None,
            "last": last_ts.isoformat(sep=" ") if last_ts else None,
        },
        "rule_hits": rule_hits or [],
    }


def to_text(report: Dict[str, Any]) -> str:
    lines = []
    lines.append("Threat Log Analyzer Report")
    lines.append("=" * 25)
    lines.append(f"Total events: {report['total_events']}")
    if report.get("time_range"):
        tr = report["time_range"]
        if tr.get("first") and tr.get("last"):
            lines.append(f"Time range: {tr['first']} -> {tr['last']}")
    lines.append("")

    lines.append("Counts:")
    for k, v in report["counts"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("")

    def section(title: str, items):
        lines.append(title + ":")
        if not items:
            lines.append("  (none)")
        else:
            for a, b in items:
                lines.append(f"  - {a}: {b}")
        lines.append("")

    section("Top failed IPs", report["top_failed_ips"])
    section("Top failed users", report["top_failed_users"])
    section("Top success IPs", report["top_success_ips"])

    lines.append("Suspicious (simple scoring):")
    if not report["suspicious"]:
        lines.append("  (none)")
    else:
        for row in report["suspicious"]:
            lines.append(f"  - {row['ip']}: fails={row['fail_count']} score={row['score']}/100")
    lines.append("")

    lines.append("Rule hits:")
    if not report.get("rule_hits"):
        lines.append("  (none)")
    else:
        for hit in report["rule_hits"]:
            lines.append(f"  - {hit['id']}: {hit['count']} ({hit.get('description','')})")
    lines.append("")

    return "\n".join(lines)


def _event_dict(e: AuthEvent) -> Dict[str, Any]:
    return {
        "kind": e.kind,
        "ip": e.ip,
        "user": e.user,
        "ts": e.ts.isoformat(sep=" ") if e.ts else None,
        "raw": e.raw,
    }


def to_jsonl(events: Iterable[AuthEvent]) -> str:
    import json

    return "\n".join(json.dumps(_event_dict(e), ensure_ascii=False) for e in events)


def to_csv(events: Iterable[AuthEvent]) -> str:
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["kind", "ip", "user", "ts", "raw"])
    for e in events:
        writer.writerow([e.kind, e.ip, e.user or "", e.ts.isoformat(sep=" ") if e.ts else "", e.raw])
    return buf.getvalue()


def to_html(report: Dict[str, Any]) -> str:
    def render_list(items):
        if not items:
            return "<li>(none)</li>"
        return "".join(f"<li><code>{a}</code>: {b}</li>" for a, b in items)

    rule_hits = report.get("rule_hits") or []
    rules_html = "".join(
        f"<li><code>{r['id']}</code>: {r['count']}<br><small>{r.get('description','')}</small></li>"
        for r in rule_hits
    ) or "<li>(none)</li>"

    tr = report.get("time_range") or {}
    time_range = ""
    if tr.get("first") and tr.get("last"):
        time_range = f"<div class=\"meta\">Time range: {tr['first']} → {tr['last']}</div>"

    return f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<title>Threat Log Analyzer Report</title>
<style>
:root {{
  --bg: #0f172a;
  --panel: #111827;
  --ink: #e5e7eb;
  --muted: #94a3b8;
  --accent: #22d3ee;
  --accent2: #a3e635;
  --danger: #f97316;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; background: radial-gradient(1200px 600px at 10% 0%, #0b1d2c, var(--bg)); color: var(--ink); }}
.container {{ max-width: 960px; margin: 40px auto; padding: 24px; }}
.header {{ display: flex; justify-content: space-between; align-items: baseline; gap: 16px; }}
.h1 {{ font-size: 28px; letter-spacing: 0.5px; }}
.meta {{ color: var(--muted); margin-top: 6px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-top: 16px; }}
.card {{ background: linear-gradient(180deg, #0b1220, var(--panel)); border: 1px solid #1f2937; padding: 16px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }}
.card h3 {{ margin: 0 0 8px; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }}
.kpi {{ font-size: 28px; color: var(--accent); }}
.list {{ padding-left: 18px; margin: 0; }}
.list li {{ margin: 6px 0; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #0b2b36; color: var(--accent2); font-size: 12px; }}
</style>
</head>
<body>
  <div class=\"container\">
    <div class=\"header\">
      <div>
        <div class=\"h1\">Threat Log Analyzer Report</div>
        {time_range}
      </div>
      <div class=\"badge\">Total events: {report['total_events']}</div>
    </div>

    <div class=\"grid\">
      <div class=\"card\">
        <h3>Counts</h3>
        <ul class=\"list\">
          {''.join(f"<li><code>{k}</code>: {v}</li>" for k, v in report['counts'].items()) or '<li>(none)</li>'}
        </ul>
      </div>
      <div class=\"card\">
        <h3>Top Failed IPs</h3>
        <ul class=\"list\">{render_list(report['top_failed_ips'])}</ul>
      </div>
      <div class=\"card\">
        <h3>Top Failed Users</h3>
        <ul class=\"list\">{render_list(report['top_failed_users'])}</ul>
      </div>
      <div class=\"card\">
        <h3>Top Success IPs</h3>
        <ul class=\"list\">{render_list(report['top_success_ips'])}</ul>
      </div>
      <div class=\"card\">
        <h3>Suspicious (score)</h3>
        <ul class=\"list\">
          {''.join(f"<li><code>{r['ip']}</code>: fails={r['fail_count']} score=<span style='color:var(--danger)'>{r['score']}</span></li>" for r in report['suspicious']) or '<li>(none)</li>'}
        </ul>
      </div>
      <div class=\"card\">
        <h3>Rule Hits</h3>
        <ul class=\"list\">{rules_html}</ul>
      </div>
    </div>
  </div>
</body>
</html>"""
