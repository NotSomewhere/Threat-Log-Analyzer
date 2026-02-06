from dataclasses import dataclass
from typing import Dict, List, Any, Optional

import re
import yaml


@dataclass
class Rule:
    id: str
    description: str
    regex: str
    severity: str

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex)


def load_rules(path: Optional[str] = None, data: Optional[str] = None) -> List[Rule]:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
    if not data:
        return []
    parsed = yaml.safe_load(data) or []
    rules: List[Rule] = []
    for item in parsed:
        rules.append(
            Rule(
                id=str(item.get("id", "RULE")),
                description=str(item.get("description", "")),
                regex=str(item.get("regex", ".*")),
                severity=str(item.get("severity", "low")),
            )
        )
    return rules


def apply_rules(lines: List[str], rules: List[Rule], max_examples: int = 3) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for rule in rules:
        pattern = rule.compiled()
        count = 0
        examples: List[str] = []
        for line in lines:
            if pattern.search(line):
                count += 1
                if len(examples) < max_examples:
                    examples.append(line)
        if count:
            hits.append(
                {
                    "id": rule.id,
                    "description": rule.description,
                    "severity": rule.severity,
                    "count": count,
                    "examples": examples,
                }
            )
    return hits
