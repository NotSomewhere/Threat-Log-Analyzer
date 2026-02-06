from threat_log_analyzer.report import summarize
from threat_log_analyzer.parsers import AuthEvent


def test_summarize_basic():
    events = [
        AuthEvent("failed_password", "1.2.3.4", "root", None, "raw"),
        AuthEvent("invalid_user", "1.2.3.4", "admin", None, "raw"),
        AuthEvent("accepted_password", "9.9.9.9", "joel", None, "raw"),
    ]
    report = summarize(events, top_n=5)
    assert report["total_events"] == 3
    assert report["counts"]["failed_password"] == 1
    assert report["counts"]["invalid_user"] == 1
    assert report["counts"]["accepted_password"] == 1
