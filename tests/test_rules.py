from threat_log_analyzer.rules import apply_rules, Rule


def test_rules_apply():
    lines = [
        "Failed password for invalid user admin from 1.2.3.4",
        "Invalid user test from 5.6.7.8",
    ]
    rules = [Rule(id="R1", description="fail", regex="Failed password", severity="low")]
    hits = apply_rules(lines, rules)
    assert hits and hits[0]["count"] == 1
