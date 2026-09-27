"""Suite-wide isolation.

Settings default to the repository's own ``artifacts/`` directory, and the
workspace API migrates and recovers the evidence store it finds there on start.
No test may touch real prepared evidence, so every test gets a private artifact
root unless it passes one explicitly.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_artifact_root(tmp_path_factory: pytest.TempPathFactory, monkeypatch) -> None:
    monkeypatch.setenv("HESTIA_ARTIFACT_ROOT", str(tmp_path_factory.mktemp("artifacts")))
