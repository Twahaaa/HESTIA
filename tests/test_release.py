import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_audited_export_is_allowlisted(tmp_path):
    destination = tmp_path / "source"
    _script("export_source").export_source(ROOT, destination)
    assert (destination / "evaluation/configs/local.json").is_file()
    assert (destination / "src/hestia/evaluation/runner.py").is_file()
    assert (destination / "docs/PRESENTATION-GUIDE.md").is_file()
    assert _script("audit_release").audit_source(destination)["checked_files"] > 100
    (destination / "artifacts/cases").mkdir(parents=True)
    (destination / "artifacts/cases" / "run.handles.json").write_text("{}")
    with pytest.raises(ValueError, match="private"):
        _script("audit_release").audit_source(destination)


def test_release_audit_refuses_populated_provider_key(tmp_path):
    for name in ("pyproject.toml", "uv.lock"):
        (tmp_path / name).write_text("placeholder")
    (tmp_path / "src/hestia").mkdir(parents=True)
    (tmp_path / "src/hestia/cli.py").write_text("pass")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/EVALUATION.md").write_text("docs")
    (tmp_path / "docs/PRESENTATION-GUIDE.md").write_text("guide")
    (tmp_path / "config.yaml").write_text("HESTIA_AGENT_API_KEY=real-secret\n")
    with pytest.raises(ValueError, match="credential"):
        _script("audit_release").audit_source(tmp_path)
    (tmp_path / "config.yaml").write_text('HESTIA_AGENT_API_KEYS=["real-one","real-two"]\n')
    with pytest.raises(ValueError, match="credential"):
        _script("audit_release").audit_source(tmp_path)
    private_path = "/".join(("", "home", "person", "Documents", "private", "code"))
    (tmp_path / "config.yaml").write_text(f"source: {private_path}\n")
    with pytest.raises(ValueError, match="absolute path"):
        _script("audit_release").audit_source(tmp_path)
