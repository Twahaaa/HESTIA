import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from hestia.config import Settings


def _read_gap(path: Path) -> float:
    payload = json.loads(path.read_text(encoding="utf-8"))
    try:
        return float(payload["gap_seconds"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Gap artifact must contain numeric gap_seconds") from exc


def prepare_data(
    settings: Settings,
    *,
    dataset_id: str | None,
    profile_path: Path | None,
    run_id: str,
    gap_seconds: float,
) -> dict[str, int | str]:
    from hestia.datasets.profiles import DatasetProfile, dataset_profiles
    from hestia.datasets.splits import SplitItem, build_split_manifest, write_split_manifest
    from hestia.ingestion.collector import collect_source
    from hestia.ingestion.sessionization import sessionize_events
    from hestia.store.repository import EvidenceRepository

    if profile_path is not None:
        profile = DatasetProfile.model_validate_json(profile_path.read_text(encoding="utf-8"))
        profiles = (profile,)
        dataset_id = profile.dataset_id
    elif dataset_id is not None:
        profiles = dataset_profiles(settings.data_root, dataset_id)
    else:
        raise ValueError("A dataset identifier or profile is required")

    repository = EvidenceRepository(settings.evidence_database)
    repository.initialize()
    repository.create_run(
        run_id,
        "running",
        {"dataset_id": dataset_id, "gap_seconds": gap_seconds, "profile": str(profile_path or "")},
    )
    counts = {
        "raw_lines": 0,
        "parse_failures": 0,
        "events": 0,
        "complete_sessions": 0,
        "unmatched": 0,
        "excluded": 0,
    }
    split_items: list[SplitItem] = []
    try:
        for profile in profiles:
            source_path = settings.data_root / "raw" / profile.source_path
            collection = collect_source(source_path, profile)
            events = [item.event for item in collection.events]
            sessions, unmatched_events = sessionize_events(events, gap_seconds=gap_seconds)
            repository.import_source(
                collection,
                sessions,
                ((event, "missing user or source IP") for event in unmatched_events),
            )
            counts["raw_lines"] += collection.raw_line_count
            counts["parse_failures"] += len(collection.failures)
            counts["events"] += len(collection.events)
            counts["complete_sessions"] += len(sessions)
            counts["unmatched"] += len(unmatched_events)
            reason = (
                f"{profile.dataset_id} annotation coverage is {profile.annotation_coverage}; "
                "no source-level benign eligibility evidence is declared"
            )
            split_items.extend(
                SplitItem(
                    item_id=session.session_id,
                    source_path=profile.source_path,
                    timestamp=session.start_time,
                    host=session.host or "",
                    content_hash=collection.content_hash,
                    eligible=False,
                    eligibility_reason=reason,
                )
                for session in sessions
            )
        repository.set_run_status(run_id, "complete")
    except Exception:
        repository.set_run_status(run_id, "failed")
        raise
    manifest = build_split_manifest(split_items)
    manifest_path = settings.artifact_root / "preparation" / f"{run_id}-splits.json"
    write_split_manifest(manifest, manifest_path)
    counts["excluded"] = sum(entry.split == "excluded" for entry in manifest.entries)
    return {
        "dataset_id": dataset_id or "",
        "run_id": run_id,
        "split_manifest": str(manifest_path),
        "split_manifest_hash": manifest.manifest_hash,
        **counts,
    }


def train_normality(
    settings: Settings, *, split_manifest_path: Path, deployment_timezone: str
) -> dict[str, Any]:
    """Train only explicitly eligible reference observations from a frozen manifest."""
    from hestia.datasets.splits import SplitManifest
    from hestia.normality.artifacts import write_artifact
    from hestia.normality.context import materialize_context_snapshot
    from hestia.normality.features import extract_session_features
    from hestia.normality.registry import MODEL_REGISTRY
    from hestia.normality.training import (
        NormalTrainingEligibility,
        TrainingObservation,
        train_normal_models,
    )
    from hestia.store.repository import EvidenceRepository

    manifest = SplitManifest.model_validate_json(split_manifest_path.read_text(encoding="utf-8"))
    reference = {entry.item_id: entry for entry in manifest.entries if entry.split == "reference"}
    repository = EvidenceRepository(settings.evidence_database)
    observations: list[TrainingObservation] = []
    for evidence in repository.iter_session_evidence():
        entry = reference.get(evidence.session.session_id)
        if entry is None:
            continue
        snapshot = materialize_context_snapshot(
            repository,
            evidence.session,
            deployment_timezone=deployment_timezone,
        )
        features = extract_session_features(
            evidence.session,
            evidence.events,
            deployment_timezone,
            snapshot.context,
        )
        content = json.dumps(
            {
                "session": evidence.session.model_dump(mode="json"),
                "events": [event.model_dump(mode="json") for event in evidence.events],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        observations.append(
            TrainingObservation(
                started_at=evidence.session.start_time,
                session_id=evidence.session.session_id,
                user=evidence.session.user,
                src_ip=evidence.session.src_ip,
                host=evidence.session.host,
                features=features,
                content_sha256=hashlib.sha256(content.encode()).hexdigest(),
                eligibility=NormalTrainingEligibility(
                    eligible=True,
                    normal=True,
                    split="training",
                    evidence_ref=evidence.evidence_ref,
                    reason=entry.reason,
                ),
            )
        )

    readiness_path = settings.artifact_root / "preparation" / "readiness.json"
    readiness_path.parent.mkdir(parents=True, exist_ok=True)
    if not observations:
        readiness = {
            "ready": False,
            "eligible_training_sessions": 0,
            "reason": "no sessions have explicit normal training eligibility",
            "split_manifest_hash": manifest.manifest_hash,
        }
        readiness_path.write_text(json.dumps(readiness, indent=2) + "\n", encoding="utf-8")
        return readiness

    result = train_normal_models(observations)
    artifact_dir = settings.artifact_root / "normality"
    for artifact in result.artifacts:
        identity = hashlib.sha256(artifact.metadata.entity_id.encode()).hexdigest()[:16]
        write_artifact(artifact, artifact_dir / f"{artifact.metadata.model_id}--{identity}.json")
    readiness = {
        "ready": all(
            artifact.metadata.observation_count
            >= MODEL_REGISTRY[artifact.metadata.model_id].warmup_observations
            for artifact in result.artifacts
        ),
        "eligible_training_sessions": len(observations),
        "artifact_count": len(result.artifacts),
        "split_manifest_hash": manifest.manifest_hash,
        "reason": "one or more entity models have incomplete warmup",
    }
    if readiness["ready"]:
        readiness["reason"] = None
    readiness_path.write_text(json.dumps(readiness, indent=2) + "\n", encoding="utf-8")
    return readiness


def calibrate_normality(
    settings: Settings, *, scores_path: Path, max_alerts_per_batch: int
) -> dict[str, Any]:
    """Freeze a held-out-normal calibration policy from an evaluation sidecar."""
    from dataclasses import asdict

    from hestia.normality.calibration import ValidationScore, calibrate_alert_budget

    rows = json.loads(scores_path.read_text(encoding="utf-8"))
    scores = [ValidationScore(**row) for row in rows]
    policy = calibrate_alert_budget(scores, max_alerts_per_batch=max_alerts_per_batch)
    payload = asdict(policy)
    path = settings.artifact_root / "normality" / "calibration.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def build_knowledge(
    settings: Settings,
    *,
    split_manifests: tuple[Path, ...],
    refresh_attack: bool,
    attack_url: str,
) -> dict[str, Any]:
    """Build the reference index offline; refresh the pinned snapshot only on request."""
    from hestia.knowledge import (
        SNAPSHOT_FILENAME,
        build_reference_index,
        build_snapshot,
        fetch_bundle,
        read_snapshot,
        write_index,
        write_snapshot,
    )
    from hestia.knowledge.cam import build_cam_documents

    snapshot_path = settings.attack_reference_root / SNAPSHOT_FILENAME
    if refresh_attack:
        local, _ = build_cam_documents(settings.data_root)
        extra = frozenset(technique for document in local for technique in document.technique_ids)
        raw, digest = fetch_bundle(attack_url, confirmed=True)
        snapshot = build_snapshot(raw, source_url=attack_url, extra_ids=extra)
        write_snapshot(snapshot, snapshot_path)
        print(
            json.dumps(
                {
                    "refreshed": attack_url,
                    "upstream_sha256": digest,
                    "techniques": len(snapshot.techniques),
                },
                indent=2,
            )
        )
    snapshot = read_snapshot(snapshot_path) if snapshot_path.is_file() else None
    index = build_reference_index(
        settings.data_root, split_manifests=split_manifests, attack_snapshot=snapshot
    )
    write_index(index, settings.knowledge_index)
    return {
        "index_path": str(settings.knowledge_index),
        "index_hash": index.index_hash,
        "documents": len(index.documents),
        "collections": list(index.collections),
        "excluded_source_paths": len(index.excluded_source_paths),
        "attack_snapshot": str(snapshot_path) if snapshot is not None else None,
    }


def run_investigation(
    settings: Settings,
    *,
    session_id: str,
    fixture_provider: bool,
    stdio: bool,
) -> dict[str, Any]:
    """Investigate one prepared session and persist the run.

    ``--fixture-provider`` selects a clearly labelled deterministic local model so
    the pipeline can be demonstrated without contacting a hosted provider. A
    fixture run is stored and reported as a fixture; it is never a hosted result.
    """
    from datetime import UTC, datetime

    from hestia.agent.contracts import CaseInput
    from hestia.agent.providers import provider_status
    from hestia.agent.runner import investigate
    from hestia.config import AgentProvider
    from hestia.runs.cases import case_id_for
    from hestia.store.repository import EvidenceRepository

    if fixture_provider:
        settings = settings.model_copy(
            update={"agent_provider": AgentProvider.fixture, "agent_model": "fixture-analyst"}
        )
    status = provider_status(settings)
    if not status.configured:
        return {"state": "unavailable", "reason": status.reason, **status.as_dict()}

    repository = EvidenceRepository(settings.evidence_database)
    repository.initialize()
    row = repository.read_session(session_id)
    if row is None:
        return {
            "state": "unavailable",
            "reason": f"no prepared session has the identifier {session_id!r}",
        }
    session = json.loads(str(row["session_json"]))
    start = datetime.fromisoformat(session["start_time"])
    case = CaseInput(
        # The workspace's opaque case identifier. A prefix of the session id is not
        # unique (every OpenSSH session shares one) and would embed a source path.
        case_id=case_id_for(session["session_id"]),
        session_id=session["session_id"],
        opened_at=datetime.now(UTC),
        session_start=start,
        session_end=datetime.fromisoformat(session["end_time"]),
        dataset_id=str(row["dataset_id"]),
        history_before=start,
    )
    script = _fixture_script() if fixture_provider else None
    run = asyncio.run(
        investigate(
            settings,
            case,
            fixture_script=script,
            stdio=stdio,
            persist=repository.save_case_run,
        )
    )
    return {
        "run_id": run.run_id,
        "state": run.state.value,
        "provider": run.provider,
        "model": run.model,
        "fixture": run.fixture,
        "tool_calls": len(run.traces),
        "hypotheses": len(run.hypotheses),
        "grounded": None if run.grounding is None else run.grounding.grounded,
        "verdict": None if run.report is None else run.report.verdict.value,
        "incomplete_reason": run.incomplete_reason,
        "usage": run.usage.model_dump(mode="json"),
    }


def evaluate_agent(args: argparse.Namespace) -> dict[str, Any]:
    """Plan or run an agent evaluation. Hosted mode needs the plan's approval token."""
    from hestia.evaluation.agent_eval import (
        HostedRefused,
        hosted_settings,
        load_config,
        plan,
        run_agent_evaluation,
        select_cases,
    )

    def fixture_settings() -> Settings:
        return Settings(_env_file=None)  # type: ignore[call-arg]

    config = load_config(args.config)
    try:
        if args.plan:
            if args.mode == "hosted":
                if config.hosted is None:
                    raise HostedRefused("the config has no hosted plan")
                settings = hosted_settings(Settings, config.hosted)
            else:
                settings = fixture_settings()
            index = (args.config.resolve().parent / config.reference_index_path).resolve()
            cases = select_cases(config, settings.evidence_database, index)
            return {
                "planned_only": True,
                "keys_configured": len(settings.agent_keys) if args.mode == "hosted" else 0,
                **plan(config, cases, mode=args.mode, limit_cases=args.limit_cases),
            }
        return run_agent_evaluation(
            args.config,
            mode=args.mode,
            output_root=fixture_settings().artifact_root / "evaluation",
            settings_factory=Settings if args.mode == "hosted" else fixture_settings,
            approval=args.approve,
            limit_cases=args.limit_cases,
        )
    except HostedRefused as exc:
        raise SystemExit(f"hosted evaluation refused (nothing was sent): {exc}") from None


def _fixture_script() -> list[Any]:
    """A deterministic analyst that actually uses the tools, then abstains.

    It retrieves the case, checks normality readiness, looks for prior activity,
    records a hypothesis, and returns insufficient_evidence because no behavioural
    model is trained in this deployment. This mirrors the honest outcome rather
    than manufacturing a verdict for a demo.
    """
    from hestia.agent.fixtures import demo_script

    return demo_script()


def main() -> None:
    parser = argparse.ArgumentParser(prog="hestia")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor")
    commands.add_parser("mcp")
    ingest = commands.add_parser("import-data")
    ingest.add_argument("--source-root", type=Path, required=True)
    parse = commands.add_parser("parse")
    parse.add_argument("path", type=Path)
    parse.add_argument("--source", required=True)
    parse.add_argument("--year", type=int, required=True)
    prepare = commands.add_parser("prepare-data")
    source = prepare.add_mutually_exclusive_group(required=True)
    source.add_argument("--dataset")
    source.add_argument("--profile", type=Path)
    prepare.add_argument("--run-id", required=True)
    gap = prepare.add_mutually_exclusive_group(required=True)
    gap.add_argument("--gap", "--gap-seconds", dest="gap_seconds", type=float)
    gap.add_argument("--gap-artifact", type=Path)
    train = commands.add_parser("train-normality")
    train.add_argument("--split-manifest", type=Path, required=True)
    train.add_argument("--deployment-timezone", default="UTC")
    calibrate = commands.add_parser("calibrate-normality")
    calibrate.add_argument("--scores", type=Path, required=True)
    calibrate.add_argument("--max-alerts-per-batch", type=int, required=True)
    knowledge = commands.add_parser("knowledge-build")
    knowledge.add_argument("--split-manifest", type=Path, action="append", default=[])
    knowledge.add_argument(
        "--refresh-attack",
        action="store_true",
        help="explicitly re-download the pinned MITRE ATT&CK snapshot",
    )
    knowledge.add_argument("--attack-url", default=None)
    investigate_case = commands.add_parser("investigate")
    investigate_case.add_argument("--session-id", required=True)
    investigate_case.add_argument(
        "--fixture-provider",
        action="store_true",
        help="use the labelled deterministic local model instead of a hosted provider",
    )
    investigate_case.add_argument(
        "--stdio",
        action="store_true",
        help="spawn the MCP server as a subprocess instead of running it in process",
    )
    commands.add_parser(
        "demo-seed",
        help=(
            "prepare the bundled synthetic log into an empty artifact root and mark it as "
            "the designated demo workspace"
        ),
    )
    evaluate_command = commands.add_parser("evaluate", help="measure stored runs offline")
    evaluate_command.add_argument("--config", type=Path, required=True)
    hdfs = commands.add_parser("evaluate-hdfs", help="run the separate HDFS v1 anomaly baseline")
    hdfs.add_argument("--archive", type=Path, required=True)
    hdfs.add_argument("--config", type=Path, default=Path("evaluation/configs/hdfs.json"))
    refined = commands.add_parser(
        "evaluate-hdfs-refined", help="compare validation-selected HDFS trace baselines"
    )
    refined.add_argument("--archive", type=Path, required=True)
    refined.add_argument(
        "--config", type=Path, default=Path("evaluation/configs/hdfs-refined.json")
    )
    inspect = commands.add_parser("inspect-hdfs", help="show raw HDFS lines for one block")
    inspect.add_argument("--archive", type=Path, required=True)
    inspect.add_argument("--block-id", required=True)
    source_labels = commands.add_parser(
        "label-sources",
        help=(
            "derive evaluation-only labels from upstream AIT-LDS/CAM-LDS conventions "
            "(private sidecar; scoring only)"
        ),
    )
    source_labels.add_argument("--output-dir", type=Path, default=None)
    agent_eval = commands.add_parser(
        "evaluate-agent",
        help="evaluate the investigation agent on a pre-registered, label-free case set",
    )
    agent_eval.add_argument("--config", type=Path, required=True)
    agent_eval.add_argument("--mode", choices=("fixture", "hosted"), default="fixture")
    agent_eval.add_argument(
        "--plan", action="store_true", help="print cases, ceilings and approval token; run nothing"
    )
    agent_eval.add_argument("--approve", help="approval token printed by --plan (hosted only)")
    agent_eval.add_argument("--limit-cases", type=int, default=None)
    args = parser.parse_args()
    if args.command == "evaluate-agent":
        # Handled before loading local settings: a fixture evaluation must not
        # read provider keys, and a hosted one validates them without echoing them.
        print(json.dumps(evaluate_agent(args), indent=2, sort_keys=True, default=str))
        return
    settings = Settings()
    if args.command == "mcp":
        from hestia.mcp.server import main as run

        run()
    elif args.command == "import-data":
        from hestia.datasets.importer import import_datasets

        result = import_datasets(args.source_root, settings.data_root)
        print(json.dumps({m.dataset_id: len(m.files) for m in result}, indent=2))
    elif args.command == "parse":
        from hestia.ingestion.parser import parse_file

        with args.path.open(errors="replace") as stream:
            events, failures = parse_file(args.source, stream, default_year=args.year)
        print(
            json.dumps(
                {
                    "events": [e.model_dump(mode="json") for e in events],
                    "failures": [f.model_dump(mode="json") for f in failures],
                }
            )
        )
    elif args.command == "prepare-data":
        gap_seconds = args.gap_seconds
        if args.gap_artifact is not None:
            gap_seconds = _read_gap(args.gap_artifact)
        result = prepare_data(
            settings,
            dataset_id=args.dataset,
            profile_path=args.profile,
            run_id=args.run_id,
            gap_seconds=gap_seconds,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "train-normality":
        result = train_normality(
            settings,
            split_manifest_path=args.split_manifest,
            deployment_timezone=args.deployment_timezone,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "calibrate-normality":
        result = calibrate_normality(
            settings,
            scores_path=args.scores,
            max_alerts_per_batch=args.max_alerts_per_batch,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "investigate":
        result = run_investigation(
            settings,
            session_id=args.session_id,
            fixture_provider=args.fixture_provider,
            stdio=args.stdio,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "demo-seed":
        from hestia.runs.demo import DemoWorkspaceError, seed_demo_workspace

        try:
            result = seed_demo_workspace(settings)
        except DemoWorkspaceError as exc:
            raise SystemExit(f"demo-seed refused: {exc}") from exc
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "evaluate":
        from hestia.evaluation.runner import evaluate

        result = evaluate(
            args.config, settings.evidence_database, settings.artifact_root / "evaluation"
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "evaluate-hdfs":
        from hestia.evaluation.hdfs import evaluate_hdfs

        result = evaluate_hdfs(args.archive, args.config, settings.artifact_root / "evaluation")
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "evaluate-hdfs-refined":
        from hestia.evaluation.hdfs_refined import evaluate_refined_hdfs

        result = evaluate_refined_hdfs(
            args.archive, args.config, settings.artifact_root / "evaluation"
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "inspect-hdfs":
        from hestia.evaluation.hdfs import inspect_block

        print(json.dumps(inspect_block(args.archive, args.block_id), indent=2))
    elif args.command == "label-sources":
        from hestia.evaluation.source_labels import write_source_labels

        result = write_source_labels(
            settings.evidence_database,
            settings.data_root / "raw",
            args.output_dir or settings.artifact_root / "evaluation" / "labels",
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "knowledge-build":
        from hestia.knowledge import ATTACK_SOURCE_URL

        result = build_knowledge(
            settings,
            split_manifests=tuple(args.split_manifest),
            refresh_attack=args.refresh_attack,
            attack_url=args.attack_url or ATTACK_SOURCE_URL,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        from hestia.datasets.catalog import list_datasets
        from hestia.normality.catalog import list_models

        print(
            json.dumps(
                {"datasets": list_datasets(settings.data_root), "models": list_models()}, indent=2
            )
        )
