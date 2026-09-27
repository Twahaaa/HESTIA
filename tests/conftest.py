"""Suite-wide isolation.

Settings default to the repository's own ``artifacts/`` directory, and the
workspace API migrates and recovers the evidence store it finds there on start.
No test may touch real prepared evidence, so every test gets a private artifact
root unless it passes one explicitly.

Settings also read a local ``.env`` by default. A developer's real provider keys
must never reach a test (or its failure output), and an invalid local file must
not change results, so the suite never reads it.
"""

from __future__ import annotations

import pytest

from hestia.agent.ratelimit import reset_shared_pacers
from hestia.config import Settings


@pytest.fixture(autouse=True)
def isolated_artifact_root(tmp_path_factory: pytest.TempPathFactory, monkeypatch) -> None:
    monkeypatch.setenv("HESTIA_ARTIFACT_ROOT", str(tmp_path_factory.mktemp("artifacts")))


@pytest.fixture(autouse=True)
def ignore_local_env_file(monkeypatch) -> None:
    monkeypatch.setitem(Settings.model_config, "env_file", None)


@pytest.fixture(autouse=True)
def fresh_rate_limit_state() -> None:
    """Pacing state is process-wide by design; each test starts from none."""
    reset_shared_pacers()
