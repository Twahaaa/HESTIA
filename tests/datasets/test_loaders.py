"""Smoke tests for dataset loaders using synthetic data."""

from pathlib import Path

import pytest

from hestia.contracts import LabelRecord
from hestia.datasets.aitlds import (
    load_aitlds_events,
    load_aitlds_labels,
    select_normal_pool,
)
from hestia.datasets.camlds import load_camlds_manifestations
from hestia.datasets.loghub import load_loghub_openssh


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def aitlds_log(tmp_path: Path) -> Path:
    """Synthetic AIT-LDS auth.log."""
    content = (
        "May 30 08:41:22 web01 sshd[20440]: "
        "Accepted password for jdoe from 10.20.4.51 port 52144 ssh2\n"
        "May 30 08:39:02 web01 sshd[20388]: "
        "Failed password for invalid user admin from 203.0.113.9 port 40112 ssh2\n"
    )
    path = tmp_path / "auth.log"
    _write_text(path, content)
    return path


@pytest.fixture
def aitlds_labels(tmp_path: Path) -> Path:
    """Synthetic AIT-LDS labels CSV."""
    content = "source,line_no,attack,attack_family,technique_ids\nauth.log,2,1,brute_force,T1110\n"
    path = tmp_path / "labels.csv"
    _write_text(path, content)
    return path


def test_aitlds_smoke(aitlds_log: Path, aitlds_labels: Path) -> None:
    """AIT-LDS loader returns events, failures, and a label sidecar."""
    events, failures, labels = load_aitlds_events(
        aitlds_log, aitlds_labels, source="auth.log", default_year=2026
    )
    assert len(events) == 2
    assert not failures
    assert labels == {
        ("auth.log", 2): LabelRecord(
            source="auth.log",
            line_no=2,
            attack=True,
            attack_family="brute_force",
            technique_ids=["T1110"],
        )
    }


def test_normal_pool_excludes_attacks(aitlds_log: Path, aitlds_labels: Path) -> None:
    """Normal pool excludes events from attacked hosts and labeled lines."""
    events, _, labels = load_aitlds_events(
        aitlds_log, aitlds_labels, source="auth.log", default_year=2026
    )
    normal = select_normal_pool(events, labels, whole_clean_hosts_only=True)
    assert len(normal) == 0  # both lines share host web01 which has an attack


def test_normal_pool_includes_clean_lines(aitlds_log: Path, aitlds_labels: Path) -> None:
    """If only the attacked line is excluded, the clean line remains."""
    events, _, labels = load_aitlds_events(
        aitlds_log, aitlds_labels, source="auth.log", default_year=2026
    )
    normal = select_normal_pool(
        events,
        labels,
        whole_clean_hosts_only=False,
        complete_sources=frozenset(e.source for e in events),
    )
    assert len(normal) == 1
    assert normal[0].event_type == "ssh_auth_success"


def test_camlds_filter_auth_relevant(tmp_path: Path) -> None:
    """Only auth-relevant CAM-LDS manifestations are returned."""
    content = (
        "technique_id,tactic,manifestation,evidence,data_source\n"
        "T1110,Credential Access,SSH brute force,auth.log,linux auth log\n"
        "T1078,Initial Access,Valid account login,wtmp,linux wtmp\n"
    )
    path = tmp_path / "manifestations.csv"
    _write_text(path, content)
    manifestations = load_camlds_manifestations(path)
    assert len(manifestations) == 1
    assert manifestations[0].technique_id == "T1110"
    assert "auth" in manifestations[0].data_source.lower()


def test_loghub_openssh_positive_count(tmp_path: Path) -> None:
    """Synthetic Loghub OpenSSH file yields a positive event count."""
    content = (
        "May 30 08:41:22 web01 sshd[20440]: "
        "Accepted password for jdoe from 10.20.4.51 port 52144 ssh2\n"
    )
    path = tmp_path / "openssh.log"
    _write_text(path, content)
    events, failures = load_loghub_openssh(path, default_year=2026)
    assert len(events) > 0
    assert events[0].event_type == "ssh_auth_success"
    assert not failures


def test_load_aitlds_labels_missing_columns(tmp_path: Path) -> None:
    """Loading labels with missing columns raises ValueError."""
    path = tmp_path / "bad_labels.csv"
    _write_text(path, "source,line_no\nauth.log,1\n")
    with pytest.raises(ValueError, match="missing columns"):
        load_aitlds_labels(path)


def test_aitlds_labels_normalize_source(tmp_path: Path) -> None:
    """AIT-LDS label sources with directory prefixes are normalized."""
    log_content = (
        "Jan 23 06:25:05 host sshd[1]: Accepted password for jdoe "
        "from 10.0.0.1 port 12345 ssh2\n"
        "Jan 23 06:25:06 host sshd[2]: Invalid user admin from 10.0.0.2 port 12346\n"
    )
    log_path = tmp_path / "auth.log"
    _write_text(log_path, log_content)
    labels_path = tmp_path / "labels.csv"
    _write_text(
        labels_path,
        "source,line_no,attack,attack_family,technique_ids\n"
        "intranet_server/auth.log,2,1,brute_force,T1110\n",
    )
    events, _, labels = load_aitlds_events(
        log_path, labels_path, source="auth.log", default_year=2026
    )
    assert len(events) == 2
    assert labels[("auth.log", 2)].attack is True
    assert labels[("auth.log", 2)].attack_family == "brute_force"


def test_aitlds_labels_normalize_source_with_canonical_override(tmp_path: Path) -> None:
    """Explicit canonical source overrides the label basename."""
    labels_path = tmp_path / "labels.csv"
    _write_text(
        labels_path,
        "source,line_no,attack,attack_family,technique_ids\n"
        "server/auth.log,1,1,brute_force,T1110\n",
    )
    labels = load_aitlds_labels(labels_path, expected_source="custom.log")
    assert ("custom.log", 1) in labels
    assert labels[("custom.log", 1)].attack is True


def test_camlds_tree_walker(tmp_path: Path) -> None:
    """CAM-LDS loader discovers auth.log files under the tree."""
    base = tmp_path / "manifestations_filtered" / "steps" / "1_test-1"
    auth_path = base / "inetfw" / "logs" / "log" / "auth.log"
    _write_text(
        auth_path,
        "Jan 23 06:25:05 host sshd[1]: Invalid user admin from 10.0.0.1 port 12345\n",
    )
    runs = load_camlds_manifestations(tmp_path / "manifestations_filtered")
    assert len(runs) == 1
    run = runs[0]
    assert run.step_id == "1_test-1"
    assert run.host == "inetfw"
    assert run.auth_log_path == auth_path
    assert run.data_source == "auth.log"


def test_camlds_legacy_csv_still_works(tmp_path: Path) -> None:
    """File inputs still use the legacy CSV loader."""
    content = (
        "technique_id,tactic,manifestation,evidence,data_source\n"
        "T1110,Credential Access,SSH brute force,auth.log,linux auth log\n"
    )
    path = tmp_path / "manifestations.csv"
    _write_text(path, content)
    manifestations = load_camlds_manifestations(path)
    assert len(manifestations) == 1
    assert manifestations[0].technique_id == "T1110"
