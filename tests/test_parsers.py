from datetime import datetime

from threat_log_analyzer.parsers import parse_auth_log


def test_parse_auth_log_with_timestamp():
    lines = [
        "Feb  6 08:11:01 server sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 53422 ssh2",
        "Feb  6 08:11:20 server sshd[555]: Accepted password for joel from 9.9.9.9 port 2222 ssh2",
    ]
    now = datetime(2026, 2, 6, 9, 0, 0)
    events = parse_auth_log(lines, now=now)
    assert len(events) == 2
    assert events[0].ts is not None
    assert events[0].ts.year == 2026
    assert events[0].ip == "1.2.3.4"
    assert events[1].kind == "accepted_password"
