"""Create an independent source snapshot from an explicit allowlist."""

import argparse
import shutil
from pathlib import Path

ROOT_FILES = (
    ".github/workflows/ci.yml",
    "README.md",
    "pyproject.toml",
    "uv.lock",
    ".python-version",
    ".env.example",
    ".gitignore",
    ".dockerignore",
    "Dockerfile",
    "compose.yaml",
    "compose.dev.yaml",
)
TREES = {
    "src": {".py"},
    "tests": {".py", ".log"},
    "scripts": {".py"},
    "docs": {".md"},
    # Pinned public MITRE ATT&CK subset, redistributed with its required attribution.
    "data/reference": {".json"},
    "evaluation/configs": {".json"},
}
FRONTEND_FILES = (
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "vite.config.ts",
    "biome.json",
    "playwright.config.ts",
    "index.html",
    ".node-version",
)


def export_source(root: Path, destination: Path) -> int:
    root, destination = root.resolve(), destination.resolve()
    if destination.exists() or destination.is_relative_to(root):
        raise ValueError("Export destination must be a new directory outside the project")
    candidates = [root / name for name in ROOT_FILES]
    candidates += [root / "frontend" / name for name in FRONTEND_FILES]
    for directory, extensions in TREES.items():
        candidates += [
            p
            for p in (root / directory).rglob("*")
            if p.is_file() and p.suffix in extensions and "__pycache__" not in p.parts
        ]
    for directory in ("src", "tests", "e2e"):
        candidates += [
            p
            for p in (root / "frontend" / directory).rglob("*")
            if p.is_file() and p.suffix in {".ts", ".tsx", ".css"}
        ]
    for path in candidates:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Symlinks cannot be exported")
        if not path.is_file():
            raise FileNotFoundError(path)
    destination.mkdir(parents=True)
    for path in candidates:
        target = destination / path.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    (destination / "data/manifests").mkdir(parents=True)
    (destination / "artifacts").mkdir()
    return len(candidates)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(
        f"Exported {export_source(Path(__file__).resolve().parents[1], args.destination)} source files"
    )
