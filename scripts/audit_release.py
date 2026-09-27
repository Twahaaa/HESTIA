"""Audit a freshly exported source snapshot before packaging it."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

FORBIDDEN_PARTS = {
    ".git",
    ".planning",
    "node_modules",
    ".venv",
    "__pycache__",
    "raw",
    "preparation",
    "test-results",
}
FORBIDDEN_NAMES = {".env", "evidence.sqlite3", "readiness.json"}
SECRET_PATTERN = re.compile(
    r"(?im)^\s*(?:HESTIA_AGENT_API_KEYS?|GROQ_API_KEY|OPENROUTER_API_KEY)\s*=\s*"
    r"(?!\s*(?:$|#|<|your-|replace-))[^\s#]+"
)
PRIVATE_PATH_PATTERN = re.compile(r"/home/[^/\s]+/(?:Documents|\.config|\.local)/")


def audit_source(root: Path) -> dict[str, int]:
    """Refuse private roots, opaque maps, archives and populated provider keys."""
    if not root.is_dir():
        raise ValueError("source export directory does not exist")
    checked = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if (
            path.is_symlink()
            or FORBIDDEN_PARTS.intersection(relative.parts)
            or (relative.parts[0] == "artifacts" and len(relative.parts) > 1)
        ):
            raise ValueError(f"private or linked export path: {relative}")
        if not path.is_file():
            continue
        if (
            path.name in FORBIDDEN_NAMES
            or path.name.endswith(".handles.json")
            or path.suffix in {".db", ".sqlite3", ".pkl", ".pickle", ".tar", ".gz"}
        ):
            raise ValueError(f"artifact or private export path: {relative}")
        if path.suffix in {".py", ".md", ".json", ".yaml", ".toml", ".example"}:
            text = path.read_text(encoding="utf-8")
            if SECRET_PATTERN.search(text):
                raise ValueError(f"populated provider credential in: {relative}")
            if PRIVATE_PATH_PATTERN.search(text):
                raise ValueError(f"private absolute path in: {relative}")
        checked += 1
    for required in (
        "pyproject.toml",
        "uv.lock",
        "src/hestia/cli.py",
        "docs/EVALUATION.md",
        "docs/PRESENTATION-GUIDE.md",
    ):
        if not (root / required).is_file():
            raise ValueError(f"missing release source: {required}")
    return {"checked_files": checked}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    print(audit_source(parser.parse_args().source))
