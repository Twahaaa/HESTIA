"""Workspace API fixtures over the bundled synthetic demo log.

No fixture here configures a reachable hosted provider. Runs use the labelled
deterministic fixture analyst, and every store lives under ``tmp_path``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hestia.api.app import create_app
from hestia.config import Settings
from hestia.runs.demo import seed_demo_workspace


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_root=tmp_path / "data",
        artifact_root=tmp_path / "artifacts",
        frontend_dist=tmp_path / "no-ui",
        agent_max_wall_seconds=30.0,
    )


@pytest.fixture
def seeded(settings: Settings) -> Settings:
    seed_demo_workspace(settings)
    return settings


@pytest.fixture
def client(seeded: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(seeded)) as test_client:
        yield test_client
