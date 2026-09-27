"""Explicit, repeatable import of the authentication-log subset."""

import shutil
from pathlib import Path

from hestia.datasets.catalog import DataFile, DatasetManifest, digest

SOURCES = {
    "ait-auth": ("ait-lds-v2.0", "https://zenodo.org/records/19483937", "2.1"),
    "cam-auth": ("cam-lds", "https://zenodo.org/records/18390561", "manifestations_filtered"),
    "openssh": (
        "loghub-openssh",
        "https://github.com/logpai/loghub/tree/master/OpenSSH",
        "OpenSSH_2k",
    ),
}


def import_datasets(source_root: Path, destination: Path) -> list[DatasetManifest]:
    """Source root must contain the three named public dataset directories.

    Copy selected files only; reject conflicting destination bytes. Rerunning an
    interrupted import is safe. Never import serialized models or agent code.
    """
    manifests = []
    for dataset_id, (directory, upstream, version) in SOURCES.items():
        source = source_root / directory
        if not source.is_dir():
            raise FileNotFoundError(f"Missing dataset directory: {directory}")
        if dataset_id == "openssh":
            selected = [source / "OpenSSH_2k.log"]
        elif dataset_id == "ait-auth":
            selected = sorted(
                [
                    *source.glob("full/gather/*/logs/auth.log*"),
                    *source.glob("full/labels/*/logs/auth.log*"),
                    *source.glob("full/dataset.yaml"),
                ]
            )
        else:
            selected = sorted(source.glob("manifestations_filtered/**/auth.log"))
        selected += sorted(
            p
            for p in source.iterdir()
            if p.is_file() and p.name.lower().startswith(("license", "readme"))
        )
        if not selected:
            raise ValueError(f"No selected files for {dataset_id}")
        entries = []
        for path in selected:
            if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
                raise ValueError("Dataset symlinks are not supported")
            relative = Path(dataset_id) / path.relative_to(source)
            target = destination / "raw" / relative
            sha = digest(path)
            if not target.resolve().is_relative_to((destination / "raw").resolve()):
                raise ValueError("Destination escapes data root")
            if target.exists() and digest(target) != sha:
                raise ValueError(f"Conflicting destination: {relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(path, target)
            role = (
                "annotation"
                if "labels" in path.parts
                else "log"
                if path.name.startswith("auth.log") or path.suffix == ".log"
                else "metadata"
            )
            entries.append(
                DataFile(path=relative.as_posix(), size=path.stat().st_size, sha256=sha, role=role)
            )
        manifest = DatasetManifest(
            dataset_id=dataset_id, upstream=upstream, version=version, files=entries
        )
        out = destination / "manifests" / f"{dataset_id}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        temporary = out.with_suffix(".tmp")
        temporary.write_text(manifest.model_dump_json(indent=2) + "\n")
        temporary.replace(out)
        manifests.append(manifest)
    return manifests
