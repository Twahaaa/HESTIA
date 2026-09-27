"""Tests for the multi-dialect auth.log parser."""

from datetime import datetime

from hestia.contracts import ParseFailure
from hestia.ingestion.parser import parse_file, parse_line


def test_debian_authlog() -> None:
    """A Debian-style auth.log line parses into an Event."""
    line = (
        "May 30 08:41:22 web01 sshd[20440]: "
        "Accepted password for jdoe from 10.20.4.51 port 52144 ssh2"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert isinstance(result, type(result)) and not isinstance(result, ParseFailure)
    assert result.event_type == "ssh_auth_success"
    assert result.user == "jdoe"
    assert result.src_ip == "10.20.4.51"
    assert result.src_port == 52144
    assert result.method == "password"
    assert result.success is True
    assert result.timestamp == datetime(2026, 5, 30, 8, 41, 22)


def test_rhel_secure() -> None:
    """An RHEL-style /var/log/secure line parses into an Event."""
    line = (
        "May 30 08:39:02 web01 sshd[20388]: "
        "Failed password for invalid user admin from 203.0.113.9 port 40112 ssh2"
    )
    result = parse_line("secure", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "ssh_auth_failure_invalid_user"
    assert result.user == "admin"
    assert result.src_ip == "203.0.113.9"
    assert result.src_port == 40112
    assert result.success is False


def test_journald_iso() -> None:
    """A journald-exported ISO timestamp line parses."""
    line = (
        "2026-05-30T08:41:22.123456+00:00 web01 sshd[20440]: "
        "Accepted publickey for jdoe from 10.20.4.51 port 52144 ssh2: "
        "RSA SHA256:abc123"
    )
    result = parse_line("journald", 1, line)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "ssh_auth_success"
    assert result.method == "publickey"
    assert result.key_fingerprint == "RSA SHA256:abc123"


def test_unparseable_returns_failure() -> None:
    """A garbage line returns a ParseFailure."""
    result = parse_line("auth.log", 1, "!!! not a syslog line !!!")
    assert isinstance(result, ParseFailure)
    assert result.source == "auth.log"
    assert result.line_no == 1


def test_missing_user_goes_to_quarantine() -> None:
    """A malformed auth line missing the user entity goes to quarantine."""
    line = (
        "May 30 08:41:22 web01 sshd[20440]: Accepted password for from 10.20.4.51 port 52144 ssh2"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert isinstance(result, ParseFailure)
    assert "Unrecognized auth message family" in result.reason


def test_event_id_unique_per_line() -> None:
    """event_id encodes source and line number."""
    line = (
        "May 30 08:41:22 web01 sshd[20440]: "
        "Accepted password for jdoe from 10.20.4.51 port 52144 ssh2"
    )
    result1 = parse_line("auth.log", 1, line, default_year=2026)
    result2 = parse_line("auth.log", 2, line, default_year=2026)
    assert not isinstance(result1, ParseFailure)
    assert not isinstance(result2, ParseFailure)
    assert result1.event_id == "auth.log:1"
    assert result2.event_id == "auth.log:2"


def test_sudo_command() -> None:
    """A sudo command line parses with target user and command."""
    line = (
        "May 30 08:42:01 web01 sudo:     jdoe : TTY=pts/1 ; "
        "PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "sudo_command"
    assert result.user == "jdoe"
    assert result.target_user == "root"
    assert result.command == "/bin/bash"
    assert result.tty == "pts/1"
    assert result.pwd == "/home/jdoe"
    assert result.success is True


def test_parse_file() -> None:
    """parse_file splits events and failures across multiple lines."""
    lines = [
        (
            "May 30 08:41:22 web01 sshd[20440]: "
            "Accepted password for jdoe from 10.20.4.51 port 52144 ssh2"
        ),
        "not a syslog line",
        (
            "May 30 08:42:01 web01 sudo:     jdoe : TTY=pts/1 ; "
            "PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash"
        ),
    ]
    events, failures = parse_file("auth.log", lines, default_year=2026)
    assert len(events) == 2
    assert len(failures) == 1
    assert events[0].event_type == "ssh_auth_success"
    assert events[1].event_type == "sudo_command"


def test_pam_session_opened() -> None:
    """PAM session opened line parses with uid."""
    line = (
        "May 30 08:41:22 web01 sshd[20440]: "
        "pam_unix(sshd:session): session opened for user jdoe(uid=1000) by (uid=0)"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "session_opened"
    assert result.user == "jdoe"
    assert result.uid == 1000
    assert result.success is True


def test_account_created() -> None:
    """useradd line parses as account_created."""
    line = (
        "May 30 08:43:14 web01 useradd[20512]: "
        "new user: name=svc-backup, UID=0, GID=0, home=/home/svc-backup, shell=/bin/bash"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "account_created"
    assert result.new_account == "svc-backup"
    assert result.uid == 0
    assert result.success is None


def test_invalid_user() -> None:
    """Invalid user line parses as invalid_user."""
    line = "May 30 08:39:03 web01 sshd[20388]: Invalid user admin from 203.0.113.9 port 40112"
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "invalid_user"
    assert result.user == "admin"
    assert result.success is False


def test_invalid_user_no_port() -> None:
    """Loghub-style invalid user line without a port parses."""
    line = "May 30 08:39:03 web01 sshd[20388]: Invalid user admin from 203.0.113.9"
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "invalid_user"
    assert result.user == "admin"
    assert result.src_ip == "203.0.113.9"
    assert result.src_port is None
    assert result.success is False


def test_failed_password_no_port() -> None:
    """Loghub-style failed password line without a port parses."""
    line = "May 30 08:39:03 web01 sshd[20388]: Failed password for admin from 203.0.113.9 ssh2"
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "ssh_auth_failure"
    assert result.user == "admin"
    assert result.src_ip == "203.0.113.9"
    assert result.src_port is None
    assert result.success is False


def test_connection_closed_by_ip() -> None:
    """Connection closed by IP only parses."""
    line = "May 30 08:39:04 web01 sshd[20388]: Connection closed by 203.0.113.9 [preauth]"
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "connection_closed_by_ip"
    assert result.src_ip == "203.0.113.9"
    assert result.success is False


def test_disconnected_from_invalid_user() -> None:
    """Disconnected from invalid user line parses."""
    line = (
        "May 30 08:39:05 web01 sshd[20388]: Disconnected from invalid user admin "
        "203.0.113.9 port 40112 [preauth]"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "disconnected_from_invalid_user"
    assert result.user == "admin"
    assert result.src_ip == "203.0.113.9"
    assert result.src_port == 40112
    assert result.success is False


def test_received_disconnect() -> None:
    """Received disconnect line parses."""
    line = (
        "May 30 08:39:06 web01 sshd[20388]: Received disconnect from "
        "203.0.113.9: 11: Bye Bye [preauth]"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "received_disconnect"
    assert result.src_ip == "203.0.113.9"
    assert result.success is False


def test_systemd_session_new() -> None:
    """systemd-logind new session line parses."""
    line = "May 30 08:39:07 web01 systemd-logind[1234]: New session 42 of user jdoe."
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "systemd_session_new"
    assert result.user == "jdoe"
    assert result.success is True


def test_su_success() -> None:
    """Successful su line parses."""
    line = "May 30 08:39:08 web01 su[1234]: Successful su for root by jdoe"
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "su_success"
    assert result.user == "jdoe"
    assert result.target_user == "root"
    assert result.success is True


def test_sudo_session_opened() -> None:
    """pam_unix sudo session opened with uids parses."""
    line = (
        "May 30 08:39:09 web01 sudo: pam_unix(sudo:session): session opened "
        "for user root(uid=0) by jdoe(uid=1000)"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "sudo_session_opened"
    assert result.target_user == "root"
    assert result.user == "jdoe"
    assert result.success is True


def test_pam_check_pass_unknown() -> None:
    """pam_unix check pass unknown user line parses."""
    line = "May 30 08:39:10 web01 sshd[20388]: pam_unix(sshd:auth): check pass; user unknown"
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "pam_check_pass_unknown"
    assert result.success is False


def test_pam_auth_failure_extracts_explicit_remote_identity() -> None:
    """PAM service failures preserve explicit rhost and user fields."""
    line = (
        "Jan 23 12:54:24 davey-mail auth: pam_unix(dovecot:auth): "
        "authentication failure; logname= uid=0 euid=0 tty=dovecot "
        "ruser=shane.watson rhost=192.168.231.56  user=shane.watson"
    )
    result = parse_line("auth.log", 1, line, default_year=2022)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "auth_failure"
    assert result.src_ip == "192.168.231.56"
    assert result.user == "shane.watson"
    assert result.success is False


def test_pam_auth_failure_does_not_invent_empty_remote_identity() -> None:
    """An empty PAM rhost remains absent and uses the generic fallback."""
    line = (
        "Jan 23 12:54:24 mail auth: pam_unix(dovecot:auth): "
        "authentication failure; logname= uid=0 euid=0 tty=dovecot "
        "ruser=alice rhost=  user=alice"
    )
    result = parse_line("auth.log", 1, line, default_year=2022)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "auth_failure"
    assert result.src_ip is None
    assert result.success is False


def test_reverse_mapping_check() -> None:
    """reverse mapping checking line parses."""
    line = (
        "May 30 08:39:11 web01 sshd[20388]: reverse mapping checking getaddrinfo "
        "for attacker.example [203.0.113.9] failed - POSSIBLE BREAK-IN ATTEMPT!"
    )
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "reverse_mapping_check"
    assert result.src_ip == "203.0.113.9"
    assert result.success is False


def test_input_userauth_request() -> None:
    """input_userauth_request invalid user line parses."""
    line = "May 30 08:39:12 web01 sshd[20388]: input_userauth_request: invalid user admin [preauth]"
    result = parse_line("auth.log", 1, line, default_year=2026)
    assert not isinstance(result, ParseFailure)
    assert result.event_type == "input_userauth_request"
    assert result.user == "admin"
    assert result.success is False
