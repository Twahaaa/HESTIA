"""Multi-dialect auth.log / secure / journald parser."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil import parser as dateutil_parser

from hestia.contracts import Event, LabelRecord, ParseFailure


class ParseError(Exception):
    """Raised when a timestamp or message cannot be parsed."""


# Syslog header: timestamp host process[pid]: message
# Supports traditional syslog (Jul 30 12:34:56) and ISO-8601 / journald exports.
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>"
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"|"
    r"(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
    r")\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Message-family regexes (deterministic parsing only, not decision logic).
# Order matters: more specific patterns are listed before generic ones.
_MESSAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ssh_auth_success",
        re.compile(
            r"^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+"
            r"from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
            r"(?:\s+ssh2(?::\s+(?P<key_fingerprint>.+))?)?$"
        ),
    ),
    (
        "ssh_auth_failure_invalid_user",
        re.compile(
            r"^Failed\s+(?P<method>\S+)\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+"
            r"from\s+(?P<src_ip>\S+)\s+(?:port\s+(?P<src_port>\d+)\s+)?"
            r"(?:ssh2)?$"
        ),
    ),
    (
        "ssh_auth_failure",
        re.compile(
            r"^Failed\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+"
            r"from\s+(?P<src_ip>\S+)\s+(?:port\s+(?P<src_port>\d+)\s+)?"
            r"(?:ssh2)?$"
        ),
    ),
    (
        "invalid_user",
        re.compile(
            r"^Invalid\s+user\s+(?P<user>\S+)\s+"
            r"from\s+(?P<src_ip>\S+)"
            r"(?:\s+port\s+(?P<src_port>\d+))?\s*$"
        ),
    ),
    (
        "connection_closed_by_user",
        re.compile(
            r"^Connection\s+closed\s+by\s+authenticating\s+user\s+"
            r"(?P<user>\S+)\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
            r"(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "connection_closed_by_invalid_user",
        re.compile(
            r"^Connection\s+closed\s+by\s+invalid\s+user\s+"
            r"(?P<user>\S+)\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
            r"(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "connection_closed_by_ip",
        re.compile(
            r"^Connection\s+closed\s+by\s+(?P<src_ip>\S+)"
            r"(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "disconnected_from_invalid_user",
        re.compile(
            r"^Disconnected\s+from\s+invalid\s+user\s+"
            r"(?P<user>\S+)\s+(?P<src_ip>\S+)"
            r"(?:\s+port\s+(?P<src_port>\d+))?"
            r"(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "disconnected_from_user",
        re.compile(
            r"^Disconnected\s+from\s+user\s+"
            r"(?P<user>\S+)\s+(?P<src_ip>\S+)"
            r"(?:\s+port\s+(?P<src_port>\d+))?"
            r"(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "disconnected",
        re.compile(
            r"^Disconnected\s+from\s+authenticating\s+user\s+"
            r"(?P<user>\S+)\s+(?P<src_ip>\S+)"
            r"(?:\s+port\s+(?P<src_port>\d+))?"
            r"(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "received_disconnect",
        re.compile(
            r"^Received\s+disconnect\s+from\s+(?P<src_ip>\S+)"
            r"(?::\s*(?P<reason>.*))?$"
        ),
    ),
    (
        "session_opened",
        re.compile(
            r"^pam_unix\((?P<pam_process>[^:]+):session\):\s+"
            r"session\s+opened\s+for\s+user\s+(?P<user>[^\s(]+)"
            r"(?:\(uid=(?P<uid>\d+)\))?\s+"
            r"by\s+\(uid=(?P<by_uid>\d+)\)$"
        ),
    ),
    (
        "session_closed",
        re.compile(
            r"^pam_unix\((?P<pam_process>[^:]+):session\):\s+"
            r"session\s+closed\s+for\s+user\s+(?P<user>\S+)$"
        ),
    ),
    (
        "sudo_session_opened",
        re.compile(
            r"^pam_unix\(sudo(?:-l)?:session\):\s+session\s+opened\s+"
            r"for\s+user\s+(?P<target_user>[^\s(]+)"
            r"(?:\(uid=(?P<target_uid>\d+)\))?\s+"
            r"by\s+(?P<user>[^\s(]+)"
            r"(?:\(uid=(?P<uid>\d+)\))?$"
        ),
    ),
    (
        "sudo_command",
        re.compile(
            r"^\s*(?P<user>\S+)\s+:\s+(?:TTY=(?P<tty>\S+)\s+;\s+)?"
            r"(?:PWD=(?P<pwd>.*?)\s+;\s+)?"
            r"(?:ENV=[^;]+\s+;\s+)?"
            r"USER=(?P<target_user>\S+)\s+;\s+"
            r"COMMAND=(?P<command>.*)$"
        ),
    ),
    (
        "auth_failure",
        re.compile(
            r"^pam_unix\((?P<pam_process>[^:]+):auth\):\s+"
            r"authentication\s+failure;\s+"
            r"(?=.*\brhost=(?P<src_ip>\S+))"
            r"(?=.*\buser=(?P<user>\S+)).*$"
        ),
    ),
    (
        "auth_failure",
        re.compile(
            r"^pam_unix\((?P<pam_process>[^:]+):auth\):\s+"
            r"authentication\s+failure;\s+"
            r".*?(?:user=(?P<user>\S+))?"
        ),
    ),
    (
        "pam_check_pass_unknown",
        re.compile(
            r"^pam_unix\((?P<pam_process>[^:]+):auth\):\s+"
            r"check\s+pass;\s+user\s+unknown$"
        ),
    ),
    (
        "pam_more_failures",
        re.compile(
            r"^PAM\s+\d+\s+more\s+authentication\s+failure(?:s)?;\s+"
            r".*?(?:user=(?P<user>\S+))?"
        ),
    ),
    (
        "su_session_opened",
        re.compile(
            r"^pam_unix\(su(?:-l)?:session\):\s+session\s+opened\s+"
            r"for\s+user\s+(?P<target_user>\S+)\s+"
            r"by\s+(?P<user>\S+)\(uid=(?P<uid>\d+)\)$"
        ),
    ),
    (
        "su_success",
        re.compile(
            r"^Successful\s+su\s+for\s+"
            r"(?P<target_user>\S+)\s+by\s+(?P<user>\S+)$"
        ),
    ),
    (
        "su_chfn",
        re.compile(
            r"^\+\s+\S+\s+"
            r"(?P<user>\S+):(?P<target_user>\S+)$"
        ),
    ),
    (
        "systemd_session_new",
        re.compile(r"^New\s+session\s+\d+\s+of\s+user\s+(?P<user>[^.\s]+)\.?$"),
    ),
    (
        "systemd_session_removed",
        re.compile(r"^Removed\s+session\s+\d+\.?$"),
    ),
    (
        "systemd_session_logged_out",
        re.compile(
            r"^Session\s+\d+\s+logged\s+out\.?\s+"
            r"Waiting\s+for\s+processes\s+to\s+exit\.?$"
        ),
    ),
    (
        "identification_missing",
        re.compile(
            r"^Did\s+not\s+receive\s+identification\s+string\s+from\s+"
            r"(?P<src_ip>\S+)(?:\s+port\s+(?P<src_port>\d+))?$"
        ),
    ),
    (
        "reverse_mapping_check",
        re.compile(
            r"^reverse\s+mapping\s+checking\s+getaddrinfo\s+for\s+"
            r"(?P<reverse_host>\S+)\s+\[(?P<src_ip>[^\]]+)\]\s+"
            r"failed\s+-\s+POSSIBLE\s+BREAK-IN\s+ATTEMPT!$"
        ),
    ),
    (
        "input_userauth_request",
        re.compile(
            r"^input_userauth_request:\s+invalid\s+user\s+"
            r"(?P<user>\S+)(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "attempted_login",
        re.compile(
            r"^Attempted\s+login\s+by\s+(?P<user>\S+)"
            r"(?:\s+\(UID:\s+(?P<uid>\d+)\))?"
            r"(?:\s+on\s+(?P<tty>\S+))?$"
        ),
    ),
    (
        "too_many_auth_failures",
        re.compile(
            r"^Disconnecting:\s+Too\s+many\s+authentication\s+failures\s+"
            r"for\s+(?P<user>\S+)(?:\s+\[preauth\])?$"
        ),
    ),
    (
        "drop_connection",
        re.compile(
            r"^drop\s+connection\s+#\d+\s+from\s+"
            r"\[(?P<src_ip>[^\]]+)\]:\d+\s+on\s+\[(?P<host_ip>[^\]]+)\]:\d+\s+"
            r"past\s+MaxStartups$"
        ),
    ),
    (
        "server_listening",
        re.compile(
            r"^Server\s+listening\s+on\s+(?P<listen_addr>\S+)\s+port\s+(?P<src_port>\d+)\.?$"
        ),
    ),
    (
        "maxstartups_throttle",
        re.compile(r"^(?:error:\s+)?(?:beginning|exited)\s+MaxStartups\s+throttling"),
    ),
    (
        "message_repeated",
        re.compile(
            r"^(?:last\s+message\s+repeated\s+(\d+)\s+time(?:s)?|"
            r"message\s+repeated\s+(\d+)\s+time(?:s)?:\s+\[.*\])$"
        ),
    ),
    (
        "account_created",
        re.compile(
            r"^new\s+user:\s+name=(?P<new_account>\S+),\s+"
            r"UID=(?P<uid>\d+),\s+GID=(?P<gid>\d+).*"
        ),
    ),
    (
        "group_created",
        re.compile(
            r"^new\s+group:\s+name=(?P<added_group>\S+),\s+"
            r"GID=(?P<gid>\d+).*"
        ),
    ),
    (
        "group_member_added",
        re.compile(r"^add\s+'(?P<user>\S+)'\s+to\s+group\s+'(?P<added_group>\S+)'$"),
    ),
    (
        "password_changed",
        re.compile(r"^password\s+changed\s+for\s+(?P<user>\S+)$"),
    ),
    (
        "cron_session_opened",
        re.compile(
            r"^pam_unix\(cron:session\):\s+session\s+opened\s+"
            r"for\s+user\s+(?P<user>\S+)$"
        ),
    ),
]


_SUCCESSFUL_EVENT_TYPES = {
    "ssh_auth_success",
    "session_opened",
    "sudo_command",
    "sudo_session_opened",
    "su_session_opened",
    "su_success",
    "su_chfn",
    "cron_session_opened",
    "systemd_session_new",
}

_FAILED_EVENT_TYPES = {
    "ssh_auth_failure",
    "ssh_auth_failure_invalid_user",
    "invalid_user",
    "connection_closed_by_user",
    "connection_closed_by_invalid_user",
    "connection_closed_by_ip",
    "disconnected",
    "disconnected_from_user",
    "disconnected_from_invalid_user",
    "received_disconnect",
    "auth_failure",
    "pam_check_pass_unknown",
    "pam_more_failures",
    "too_many_auth_failures",
    "reverse_mapping_check",
    "input_userauth_request",
    "attempted_login",
    "drop_connection",
    "maxstartups_throttle",
}


def _to_int(value: str | None) -> int | None:
    return int(value) if value is not None else None


def parse_timestamp(
    raw: str,
    default_year: int | None = None,
    timezone: str | None = None,
    dst_fold: int | None = None,
) -> datetime:
    """Parse a syslog or ISO-8601 timestamp.

    Args:
        raw: Timestamp string.
        default_year: Year to assume for traditional syslog stamps that omit it.

    Returns:
        An aware UTC datetime when the input has an offset or ``timezone`` is
        supplied. Legacy yearless calls without a timezone remain naive.

    Raises:
        ParseError: If the timestamp cannot be parsed.
    """
    try:
        if default_year is None and not re.match(r"^\d{4}-", raw):
            raise ParseError("Yearless timestamp requires an explicit default year")
        dt = dateutil_parser.parse(raw, default=datetime(default_year or 1970, 1, 1))
        if dt.tzinfo is not None:
            return dt.astimezone(UTC)
        if timezone is not None:
            try:
                zone = ZoneInfo(timezone)
            except ZoneInfoNotFoundError as exc:
                raise ParseError(f"Unknown timezone: {timezone!r}") from exc
            first = dt.replace(tzinfo=zone, fold=0)
            second = dt.replace(tzinfo=zone, fold=1)
            if first.utcoffset() != second.utcoffset():
                if dst_fold not in {0, 1}:
                    raise ParseError(f"Ambiguous local timestamp: {raw!r}")
                localized = dt.replace(tzinfo=zone, fold=dst_fold)
            else:
                localized = first
            round_trip = localized.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
            if round_trip != dt:
                raise ParseError(f"Nonexistent local timestamp: {raw!r}")
            return localized.astimezone(UTC)
        return dt
    except (ValueError, OverflowError, TypeError) as exc:
        raise ParseError(f"Unparseable timestamp: {raw!r}") from exc


def _derive_success(event_type: str) -> bool | None:
    if event_type in _SUCCESSFUL_EVENT_TYPES:
        return True
    if event_type in _FAILED_EVENT_TYPES:
        return False
    return None


def _extract_fields(match: re.Match[str]) -> dict[str, object]:
    """Map regex groups to Event fields."""
    groups = match.groupdict()
    return {
        "src_ip": groups.get("src_ip"),
        "src_port": _to_int(groups.get("src_port")),
        "user": groups.get("user"),
        "target_user": groups.get("target_user"),
        "method": groups.get("method"),
        "key_fingerprint": groups.get("key_fingerprint"),
        "command": groups.get("command"),
        "tty": groups.get("tty"),
        "pwd": groups.get("pwd"),
        "uid": _to_int(groups.get("uid")),
        "ruser": groups.get("ruser"),
        "new_account": groups.get("new_account"),
        "added_group": groups.get("added_group"),
    }


def parse_line(
    source: str,
    line_no: int,
    raw_line: str,
    default_year: int | None = None,
    timezone: str | None = None,
    dst_fold: int | None = None,
) -> Event | ParseFailure:
    """Parse a single auth-log line into an ``Event`` or ``ParseFailure``.

    Args:
        source: Dataset or file source name.
        line_no: 1-based line number in the source file.
        raw_line: Raw log line.
        default_year: Year to assume for traditional syslog timestamps.

    Returns:
        ``Event`` if the line is recognized, otherwise ``ParseFailure``.
    """
    stripped = raw_line.rstrip("\r\n")
    if not stripped.strip():
        return ParseFailure(
            source=source,
            line_no=line_no,
            raw_line=stripped,
            reason="Empty line",
        )

    header = _SYSLOG_RE.match(stripped)
    if not header:
        return ParseFailure(
            source=source,
            line_no=line_no,
            raw_line=stripped,
            reason="Unrecognized syslog header",
        )

    ts_raw = header.group("timestamp")
    try:
        timestamp = parse_timestamp(
            ts_raw, default_year=default_year, timezone=timezone, dst_fold=dst_fold
        )
    except ParseError as exc:
        return ParseFailure(
            source=source,
            line_no=line_no,
            raw_line=stripped,
            reason=str(exc),
        )

    host = header.group("host")
    process = header.group("process").strip()
    pid = _to_int(header.group("pid"))
    message = header.group("message")

    for event_type, pattern in _MESSAGE_PATTERNS:
        match = pattern.match(message)
        if match:
            fields = _extract_fields(match)
            return Event(
                event_id=f"{source}:{line_no}",
                source=source,
                line_no=line_no,
                timestamp=timestamp,
                host=host,
                process=process,
                pid=pid,
                event_type=event_type,
                message=message,
                raw_message=stripped,
                success=_derive_success(event_type),
                **fields,  # type: ignore[arg-type]
            )

    return ParseFailure(
        source=source,
        line_no=line_no,
        raw_line=stripped,
        reason="Unrecognized auth message family",
    )


def parse_file(
    source: str,
    lines: Iterable[str],
    default_year: int | None = None,
) -> tuple[list[Event], list[ParseFailure]]:
    """Parse an iterable of log lines.

    Args:
        source: Dataset or file source name.
        lines: Iterable of raw log lines.
        default_year: Year to assume for traditional syslog timestamps.

    Returns:
        Tuple of (events, parse_failures).
    """
    events: list[Event] = []
    failures: list[ParseFailure] = []
    for line_no, raw_line in enumerate(lines, start=1):
        result = parse_line(source, line_no, raw_line, default_year=default_year)
        if isinstance(result, Event):
            events.append(result)
        else:
            failures.append(result)
    return events, failures


def parse_file_with_labels(
    source: str,
    lines: Iterable[str],
    labels: dict[tuple[str, int], LabelRecord] | None = None,
    default_year: int | None = None,
) -> tuple[list[Event], list[ParseFailure]]:
    """Parse log lines and keep labels in a sidecar; do not attach labels to events.

    Args:
        source: Dataset or file source name.
        lines: Iterable of raw log lines.
        labels: Optional sidecar label map keyed by ``(source, line_no)``.
        default_year: Year to assume for traditional syslog timestamps.

    Returns:
        Tuple of (events, parse_failures). Labels remain in the provided dict.
    """
    return parse_file(source, lines, default_year=default_year)
