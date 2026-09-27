import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/export_source.py"
spec = importlib.util.spec_from_file_location("export_source", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_export_excludes_private_material(tmp_path):
    root = SCRIPT.parent.parent
    destination = tmp_path / "source"
    assert module.export_source(root, destination) > 20
    assert (destination / "src/hestia/api/app.py").is_file()
    assert (destination / "frontend/package-lock.json").is_file()
    assert not (destination / ".planning").exists()
    assert not (destination / ".env").exists()
    assert not (destination / "data/raw").exists()
    assert not (destination / ".git").exists()
    assert (destination / "frontend/e2e/case.spec.ts").is_file()
    assert (destination / "frontend/playwright.config.ts").is_file()
    assert (destination / "docs/DEMO.md").is_file()
    assert not list(destination.rglob("*.handles.json"))
    assert not (destination / "frontend/test-results").exists()
    assert not (destination / "frontend/node_modules").exists()
    with pytest.raises(ValueError):
        module.export_source(root, destination)
