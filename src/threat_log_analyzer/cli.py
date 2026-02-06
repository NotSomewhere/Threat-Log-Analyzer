import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
from importlib import resources

from .parsers import parse_auth_log
from .report import summarize, to_text, to_html, to_csv, to_jsonl
from .rules import load_rules, apply_rules


def _parse_duration(value: str) -> timedelta:
    value = value.strip().lower()
    if value.isdigit():
        return timedelta(hours=int(value))
    num = ""
    unit = ""
    for ch in value:
        if ch.isdigit():
            num += ch
        else:
            unit += ch
    if not num or not unit:
        raise ValueError("Invalid duration format. Use like 30m, 24h, 7d.")
    n = int(num)
    if unit == "s":
        return timedelta(seconds=n)
    if unit == "m":
        return timedelta(minutes=n)
    if unit == "h":
        return timedelta(hours=n)
    if unit == "d":
        return timedelta(days=n)
    if unit == "w":
        return timedelta(weeks=n)
    raise ValueError("Invalid duration unit. Use s, m, h, d, w.")


def _load_default_rules() -> str:
    try:
        return resources.files("threat_log_analyzer").joinpath("rules/default.yaml").read_text(encoding="utf-8")
    except Exception:
        return ""


def main() -> None:
    p = argparse.ArgumentParser(
        prog="tla",
        description="Threat Log Analyzer: parse auth/ssh logs and summarize suspicious activity.",
    )
    p.add_argument("logfile", type=Path, help="Path to auth.log / ssh log file")
    p.add_argument("--json", action="store_true", help="Output JSON instead of text")
    p.add_argument("--top", type=int, default=10, help="Show top N IPs/users (default: 10)")
    p.add_argument("--since", type=str, help="Only include events within duration (e.g., 24h, 7d, 30m)")
    p.add_argument("--html", type=Path, help="Write HTML report to file")
    p.add_argument("--csv", type=Path, help="Write CSV events to file")
    p.add_argument("--jsonl", type=Path, help="Write JSONL events to file")
    p.add_argument("--rules", type=Path, help="Path to YAML rules file")
    args = p.parse_args()

    if not args.logfile.exists():
        raise SystemExit(f"File not found: {args.logfile}")

    lines = args.logfile.read_text(errors="ignore").splitlines()
    now = datetime.now()
    events = parse_auth_log(lines, now=now)

    if args.since:
        try:
            delta = _parse_duration(args.since)
        except ValueError as e:
            raise SystemExit(str(e))
        cutoff = now - delta
        events = [e for e in events if e.ts is None or e.ts >= cutoff]

    rule_hits = []
    if args.rules:
        if not args.rules.exists():
            raise SystemExit(f"Rules file not found: {args.rules}")
        rules = load_rules(path=str(args.rules))
        rule_hits = apply_rules(lines, rules)
    else:
        local_rules = Path("rules/default.yaml")
        if local_rules.exists():
            rules = load_rules(path=str(local_rules))
            rule_hits = apply_rules(lines, rules)
        else:
            data = _load_default_rules()
            if data:
                rules = load_rules(data=data)
                rule_hits = apply_rules(lines, rules)

    report = summarize(events, top_n=args.top, rule_hits=rule_hits)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(to_text(report))

    if args.html:
        args.html.write_text(to_html(report), encoding="utf-8")

    if args.csv:
        args.csv.write_text(to_csv(events), encoding="utf-8")

    if args.jsonl:
        args.jsonl.write_text(to_jsonl(events), encoding="utf-8")


if __name__ == "__main__":
    main()
