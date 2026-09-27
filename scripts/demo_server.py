"""Serve the workspace over a freshly seeded synthetic demo workspace.

Used by the end-to-end tests and for a local demo without Docker:

    uv run python scripts/demo_server.py --artifact-root artifacts/demo-workspace --fresh

``--fresh`` deletes the artifact root first, but only when it is empty or is a
designated demo workspace (it carries the marker written by `hestia demo-seed`).
It refuses to touch any other directory.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def _clear_demo_root(root: Path) -> None:
    if not root.exists():
        return
    if (root / "demo-workspace.json").is_file() or not any(root.iterdir()):
        shutil.rmtree(root)
        return
    raise SystemExit(f"refusing to clear {root}: it is not a designated demo workspace")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--pace",
        type=float,
        default=0.0,
        help="seconds before each scripted fixture turn, so a demo run can be watched",
    )
    parser.add_argument("--fresh", action="store_true", help="start from an empty demo workspace")
    args = parser.parse_args()

    import uvicorn

    from hestia.api.app import create_app
    from hestia.config import Settings
    from hestia.runs.demo import seed_demo_workspace

    if args.fresh:
        _clear_demo_root(args.artifact_root)
    settings = Settings(
        artifact_root=args.artifact_root,
        agent_fixture_pace_seconds=args.pace,
    )
    seed_demo_workspace(settings)
    uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
