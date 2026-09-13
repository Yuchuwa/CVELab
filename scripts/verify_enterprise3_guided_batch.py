#!/usr/bin/env python3
"""Run a controlled batch of Guided-Agent template experiments.

Each case is isolated by its scenario name.  By default cases run serially;
``--parallel N`` enables a bounded number of concurrent trials when the host
has enough Docker/ContainerLab capacity:

    generate -> deploy/setup -> Guided Agent -> objective verification -> destroy

The cases are deliberately explicit.  This keeps the experiment comparable and
avoids the random combinations produced by the generic ``cvelab batch`` command.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import ipaddress
import json
import os
import re
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - workers run on Linux ContainerLab hosts.
    fcntl = None


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from dotenv import load_dotenv
except ImportError:  # The caller may provide all settings through the environment.
    load_dotenv = None

from clab_builder.orchestrator.composer.scenario import ScenarioPipeline
from clab_builder.orchestrator.composer.sysfield_exporter import SysFieldExporter
from clab_builder.orchestrator.composer.verifier import (
    ScenarioVerifier,
    build_entry_discovery_points,
)
from clab_builder.shared.models.artifact_contracts import (
    AgentExposureProfile,
    load_ground_truth,
    load_scenario_manifest,
    load_verification_result,
    normalize_agent_context,
    normalize_agent_exposure_profile,
    normalize_batch_state,
    normalize_batch_summary,
    normalize_noise_activity_config,
)


# Keep the baseline and the controlled slot substitutions together.  The order
# is part of the experiment record and must not be randomized.
CASES: tuple[dict[str, object], ...] = (
    {
        "id": "b00-baseline",
        "cves": ["CVE-2012-1823", "CVE-2018-16509", "CVE-2019-9193"],
        "purpose": "successful three-hop baseline",
    },
    {
        "id": "b01-dmz-middleware",
        "cves": ["CVE-2014-3120", "CVE-2018-16509", "CVE-2019-9193"],
        "purpose": "replace dmz-web with middleware RCE",
    },
    {
        "id": "b02-dmz-web-variant",
        "cves": ["CVE-2021-42013", "CVE-2018-16509", "CVE-2019-9193"],
        "purpose": "replace dmz-web with another reusable web RCE",
    },
    {
        "id": "b03-app-middleware",
        "cves": ["CVE-2012-1823", "CVE-2014-3120", "CVE-2019-9193"],
        "purpose": "replace app-service with middleware RCE",
    },
    {
        "id": "b04-app-solr",
        "cves": ["CVE-2012-1823", "CVE-2019-17558", "CVE-2019-9193"],
        "purpose": "replace app-service with Solr RCE",
    },
    {
        "id": "b05-dual-variant",
        "cves": ["CVE-2022-22965", "CVE-2022-24816", "CVE-2019-9193"],
        "purpose": "replace both entry and app atoms",
    },
    {
        "id": "b06-data-ssh-variant",
        "cves": ["CVE-2012-1823", "CVE-2018-16509", "CVE-2018-10933"],
        "purpose": "data-layer protocol/tool dependency variant",
    },
)


CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
MGMT_NETWORK_NAME = "cvelab-range-mgmt-v2"
# /23 (510 usable IPs) so high-node-count scenarios (50 nodes) can run at
# parallel 8+ without hitting the /24 (254 IP) cap. 172.30.240.0/23 covers
# 172.30.240.0 - 172.30.241.255; the next /23 starts at .242, etc.
MGMT_SUBNETS = [f"172.30.{240 + 2*i}.0/23" for i in range(8)]
MGMT_CAPACITY = 510
CONTROL_SUBNETS = [f"172.31.{octet}.0/28" for octet in range(240, 256)] + [
    f"10.254.{octet}.0/28" for octet in range(240, 256)
]
INFRA_RETRY_STAGES = {
    "worker_launch", "worker_timeout", "deploy", "scheduler_conflict",
    "agent_transport", "agent_preflight", "cleanup_failed",
}
# API error classes that the coordinator handles specially (not as ordinary
# agent failures). See WORK_PROGRESS_REPORT 2026-07-25 'API error triage'.
FATAL_API_STAGE = "agent_quota_exhausted"
RATE_LIMIT_API_STAGE = "agent_rate_limit"
# Cap paused-case re-queues so a permanently rate-limited case cannot loop
# forever. Each pause is one launch; beyond this the case is finalized as
# a rate-limit failure.
MAX_RATE_LIMIT_PAUSES = 3
# Cooldown before a paused case is eligible for re-queue, so the gateway
# rate-limit window can clear.
RATE_LIMIT_COOLDOWN_S = 60


def _api_error_action(failure_stage: str, pauses: int) -> str:
    """Return the coordinator action for a classified Agent API failure."""
    if failure_stage == FATAL_API_STAGE:
        return "stop"
    if failure_stage == RATE_LIMIT_API_STAGE:
        return "finalize" if pauses > MAX_RATE_LIMIT_PAUSES else "pause"
    return "ordinary"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    """Persist coordinator state without ever exposing partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        # Batch execution normally runs through sudo for Docker/ContainerLab,
        # but the experiment records belong to the invoking researcher.  Keep
        # them readable for resume and analysis after the privileged process
        # exits.  SUDO_UID/GID are supplied by sudo and absent in normal runs.
        try:
            owner_uid = int(os.environ.get("SUDO_UID", ""))
            owner_gid = int(os.environ.get("SUDO_GID", ""))
            os.chown(path, owner_uid, owner_gid)
        except (TypeError, ValueError, OSError):
            pass
        os.chmod(path, 0o644)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def physical_lab_name(run_id: str, case_id: str) -> str:
    """Map a logical experiment case to a Docker-safe, batch-unique lab."""
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:16]
    return f"e3-{run_id[:8]}-{digest}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases",
        default="all",
        help="Comma-separated case IDs, or 'all' (default).",
    )
    parser.add_argument(
        "--case-manifest",
        default="",
        help="JSON manifest produced by generate_enterprise3_matrix.py.",
    )
    parser.add_argument(
        "--template",
        default="enterprise_3tier",
        help="Topology template used to generate cases (default: enterprise_3tier).",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="Required positive cap when --case-manifest is used.",
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Zero-based manifest offset; use with --max-cases to run a disjoint shard.",
    )
    parser.add_argument(
        "--output",
        default="data/scenarios_guided_batch",
        help="Root directory for generated scenarios and summary.json.",
    )
    parser.add_argument(
        "--reuse-scenarios-from",
        default="",
        help=(
            "Copy fixed fixtures from a completed batch instead of generating "
            "scenarios again. Historical results are left untouched."
        ),
    )
    parser.add_argument("--templates-dir", default="templates")
    parser.add_argument("--atoms-dir", default="data/atoms")
    parser.add_argument("--max-turns", type=int, default=300)
    parser.add_argument(
        "--agent-timeout",
        type=int,
        default=3600,
        help="Maximum seconds for one Agent subprocess (default: 3600).",
    )
    parser.add_argument(
        "--strict-guide-compatibility",
        action="store_true",
        help="Deprecated compatibility flag; Guide alignment warnings never block Agent.",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=4,
        metavar="N",
        help="Maximum number of independent Range worker processes (default: 4).",
    )
    parser.add_argument(
        "--resume-parallel",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Worker concurrency for unfinished cases during --resume. This "
            "does not alter the initial batch fingerprint."
        ),
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--api-key", default=os.getenv("LLM_API_KEY", ""))
    parser.add_argument("--base-url", default=os.getenv("LLM_BASE_URL", ""))
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", ""))
    parser.add_argument(
        "--agent-runner",
        choices=("claude", "openai"),
        default="claude",
        help="Agent runner harness: claude (claude_agent_sdk, default) or "
             "openai (openai SDK, no built-in Agent/Task tools, avoids "
             "sub-agent model-not-found issues on gateways without haiku).",
    )
    parser.add_argument(
        "--agent-context",
        choices=(
            "guided", "no-guide", "no-hint", "l0", "l1",
            "l1-entry-discovery", "l2",
        ),
        default="guided",
        help="Agent context: guided, no-guide, no-hint (legacy alias), or "
             "difficulty level l0/l1/l2 (l0=entry IP only, l1=+topology, "
             "l1-entry-discovery=unlabeled entry candidates, "
             "l2=+CVE+credentials). Default: guided.",
    )
    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="Generate and preflight scenarios without deploying or calling the Agent.",
    )
    parser.add_argument(
        "--environment-only",
        action="store_true",
        help="Deploy and verify environment/attack graph without calling the Agent.",
    )
    parser.add_argument("--resume", action="store_true", help="Resume an interrupted batch in the same output directory.")
    parser.add_argument(
        "--cleanup-only", action="store_true",
        help="Clean this batch's recorded and run-labeled resources without generating or running cases.",
    )
    parser.add_argument(
        "--case-timeout", type=int, default=0,
        help="Worker wall-clock timeout; default is max(1800, agent_timeout + 1800).",
    )
    parser.add_argument(
        "--strict-success-exit", action="store_true",
        help="Return non-zero when any completed Range has a research failure.",
    )
    parser.add_argument(
        "--live-output", action="store_true",
        help="Stream each worker log to the terminal with a case-id prefix.",
    )
    parser.add_argument(
        "--noise-level", default="none",
        help="Noise level key from the template's noise_levels (none/low/medium/high). "
             "Inserts benign decoy nodes into zone LANs; orthogonal to --agent-context.",
    )
    parser.add_argument(
        "--noise-activity", choices=("off", "normal"), default=None,
        help="Optional local benign workload mode. Explicitly passing off/normal "
        "uses the versioned high-noise topology with idle/active clients; "
        "omitting it preserves legacy topology generation.",
    )
    parser.add_argument(
        "--noise-interval-min", type=float, default=2.0,
        help="Minimum seconds between benign workload rounds (default: 2).",
    )
    parser.add_argument(
        "--noise-interval-max", type=float, default=5.0,
        help="Maximum seconds between benign workload rounds (default: 5).",
    )
    parser.add_argument(
        "--noise-duration", type=float, default=0.0,
        help="Benign workload duration in seconds; zero runs until cleanup.",
    )
    parser.add_argument(
        "--noise-max-failures", type=int, default=0,
        help="Maximum failed workload operations per client before invalidating activity.",
    )
    parser.add_argument(
        "--sysarmor",
        action="store_true",
        help="Patch target nodes and install the pinned SysArmor rc.5 runtime before attack evaluation.",
    )
    parser.add_argument(
        "--sysarmor-detection",
        action="store_true",
        help="When --sysarmor is enabled, run the deterministic reference attack and record Signal count delta.",
    )
    parser.add_argument(
        "--sysarmor-signal-window",
        type=int,
        default=30,
        help="Seconds to wait after the reference attack before reading recent SysArmor Signals.",
    )
    parser.add_argument("--worker-spec", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def noise_activity_config(args: argparse.Namespace) -> dict[str, Any]:
    """Return the canonical public activity config used by every batch arm."""
    mode = getattr(args, "noise_activity", None) or "off"
    config = normalize_noise_activity_config(
        {
            "mode": mode,
            "profile_version": "passive-v2",
            "activity_version": "activity-v3" if getattr(args, "noise_activity", None) is not None else "",
            "interval_min_seconds": getattr(args, "noise_interval_min", 2.0),
            "interval_max_seconds": getattr(args, "noise_interval_max", 5.0),
            "duration_seconds": getattr(args, "noise_duration", 0.0),
            "max_failed_requests": getattr(args, "noise_max_failures", 0),
            "require_data_plane_ready": True,
        },
        mode=mode,
        seed=int(getattr(args, "seed", 0) or 0),
    )
    return config.model_dump(mode="json")


def select_cases(value: str, cases: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    if value.strip().lower() == "all":
        return list(cases)
    wanted = [item.strip() for item in value.split(",") if item.strip()]
    known = {case["id"]: case for case in cases}
    unknown = [item for item in wanted if item not in known]
    if unknown:
        raise SystemExit(
            "Unknown case ID(s): " + ", ".join(unknown)
            + "\nAvailable: " + ", ".join(known)
        )
    return [known[item] for item in wanted]


def validate_parallelism(parallel: int) -> None:
    if parallel < 1:
        raise ValueError("--parallel must be at least 1")


def load_manifest_cases(
    path_value: str, *, expected_template: str = ""
) -> tuple[dict[str, object], ...]:
    path = Path(path_value)
    if not path.is_absolute():
        path = ROOT / path
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read case manifest {path}: {exc}") from exc
    declared_template = str(payload.get("template") or "") if isinstance(payload, dict) else ""
    if expected_template and declared_template and declared_template != expected_template:
        raise SystemExit(
            f"Case manifest template differs: {declared_template} != {expected_template}"
        )
    raw_cases = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(raw_cases, list):
        raise SystemExit("Case manifest must contain a 'cases' list")
    cases = []
    for item in raw_cases:
        if not isinstance(item, dict) or not item.get("id") or not isinstance(item.get("cves"), list):
            raise SystemExit("Every manifest case requires id and cves")
        cases.append({
            "id": str(item["id"]),
            "cves": [str(cve) for cve in item["cves"]],
            "purpose": str(item.get("purpose", "matrix-generated combination")),
            "asset_variants": dict(item.get("asset_variants") or {}),
            "slot_atoms": dict(item.get("slot_atoms") or {}),
        })
    return tuple(cases)


def validate_cases(cases: list[dict[str, object]]) -> None:
    seen: set[str] = set()
    physical: set[str] = set()
    for case in cases:
        case_id = str(case.get("id") or "")
        if not CASE_ID_PATTERN.fullmatch(case_id):
            raise SystemExit(f"Illegal case ID {case_id!r}; use letters, digits, '.', '_' or '-'")
        if case_id in seen:
            raise SystemExit(f"Duplicate case ID in batch manifest: {case_id}")
        seen.add(case_id)
        # The digest is deliberately case-only; duplicate IDs are the only way
        # this can collide within a run, but keep the check explicit.
        digest = hashlib.sha256(case_id.encode()).hexdigest()[:16]
        if digest in physical:
            raise SystemExit(f"Lab-name collision for case ID: {case_id}")
        physical.add(digest)


def _reuse_source_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    if not (path / "batch_state.json").is_file():
        raise SystemExit(
            "--reuse-scenarios-from requires a completed batch directory with "
            f"batch_state.json: {path}"
        )
    return path


def _load_reuse_source(
    source_root: Path,
    selected: list[dict[str, object]],
    *, agent_context: str,
    noise_level: str,
) -> dict[str, Any]:
    """Validate fixed fixtures before copying them into a new batch output."""
    try:
        source = json.loads((source_root / "batch_state.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read reusable batch state: {exc}") from exc
    cases = source.get("cases")
    if not isinstance(cases, dict):
        raise SystemExit("Reusable batch state has no case map")

    import yaml

    for case in selected:
        case_id = str(case["id"])
        item = cases.get(case_id)
        if not isinstance(item, dict):
            raise SystemExit(f"Reusable batch is missing case {case_id}")
        source_case = item.get("case") or {}
        if list(source_case.get("cves") or []) != list(case.get("cves") or []):
            raise SystemExit(f"Reusable fixture CVEs differ for {case_id}")
        scenario_dir = Path(str(item.get("scenario_dir") or ""))
        required = ("scenario.yaml", "ground_truth.json", "clab.yaml", "ansible")
        if not scenario_dir.is_dir() or any(not (scenario_dir / name).exists() for name in required):
            raise SystemExit(f"Reusable fixture is incomplete for {case_id}: {scenario_dir}")
        try:
            manifest = yaml.safe_load((scenario_dir / "scenario.yaml").read_text()) or {}
            ground_truth = json.loads((scenario_dir / "ground_truth.json").read_text())
            topology = yaml.safe_load((scenario_dir / "clab.yaml").read_text()) or {}
            fixture_context = normalize_agent_context(manifest.get("agent_context", "guided"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Cannot validate reusable fixture {case_id}: {exc}") from exc
        if (
            not isinstance(topology, dict)
            or topology.get("name") != item.get("lab_name")
            or not isinstance(topology.get("topology"), dict)
        ):
            raise SystemExit(f"Reusable fixture topology is invalid for {case_id}")
        if fixture_context != agent_context:
            raise SystemExit(
                f"Reusable fixture context differs for {case_id}: "
                f"{fixture_context} != {agent_context}"
            )
        if noise_level == "none" and ground_truth.get("noise_nodes"):
            raise SystemExit(f"Reusable fixture has noise nodes but this run requests none: {case_id}")
    return source


def _copy_reused_scenario(source_dir: Path, target_dir: Path, lab_name: str) -> dict[str, str]:
    """Copy one immutable fixture while discarding prior execution evidence."""
    import yaml

    if target_dir.exists():
        raise SystemExit(f"Refusing to overwrite reusable scenario target: {target_dir}")
    try:
        source_clab = yaml.safe_load((source_dir / "clab.yaml").read_text()) or {}
        source_lab_name = str(source_clab.get("name") or source_dir.name)
    except OSError as exc:
        raise SystemExit(f"Cannot read reusable topology {source_dir}: {exc}") from exc

    def ignore_runtime_artifacts(_path: str, names: list[str]) -> set[str]:
        return {
            name for name in names
            if name in {"agent_workspace", "verify_result.json"}
            or name.startswith("clab-")
        }

    try:
        shutil.copytree(source_dir, target_dir, ignore=ignore_runtime_artifacts)
        old = source_lab_name.encode()
        new = lab_name.encode()
        for artifact in target_dir.rglob("*"):
            if artifact.is_file():
                payload = artifact.read_bytes()
                if old in payload:
                    artifact.write_bytes(payload.replace(old, new))
    except Exception:
        if target_dir.exists():
            shutil.rmtree(target_dir)
        raise

    try:
        copied_clab = yaml.safe_load((target_dir / "clab.yaml").read_text()) or {}
        copied_truth = json.loads((target_dir / "ground_truth.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Copied reusable fixture is unreadable: {exc}") from exc
    if copied_clab.get("name") != lab_name or copied_truth.get("scenario") != lab_name:
        raise SystemExit(f"Copied reusable fixture did not receive lab name {lab_name}")
    return {
        "source_scenario_dir": str(source_dir),
        "source_lab_name": source_lab_name,
    }


def _prepare_reused_scenarios(
    state: dict[str, Any], source: dict[str, Any], output_dir: Path,
) -> None:
    """Populate a new batch with copied fixtures so _generate_cases is skipped."""
    source_cases = source["cases"]
    for case_id in state["selected_case_ids"]:
        item = state["cases"][case_id]
        source_item = source_cases[case_id]
        target_dir = Path(item["scenario_dir"])
        copied = _copy_reused_scenario(
            Path(source_item["scenario_dir"]), target_dir, item["lab_name"]
        )
        item["status"] = "generated"
        item["scenario_reuse"] = copied
    state["scenario_reuse"] = {
        "source_batch": str(source.get("_source_root", "")),
        "source_run_id": str(source.get("run_id", "")),
        "mode": "copied_fixed_fixture",
    }


def _resume_contract_matches(
    state: dict[str, Any], selected: list[dict[str, object]], args: argparse.Namespace,
) -> bool:
    """Allow a scheduler-only resume across a runner fingerprint revision."""
    options = state.get("options") or {}
    expected = {
        "template": str(getattr(args, "template", "enterprise_3tier")),
        "environment_only": bool(args.environment_only),
        "generate_only": bool(args.generate_only),
        "agent_timeout": int(args.agent_timeout),
        "max_turns": int(args.max_turns),
        "seed": int(args.seed),
        "case_timeout": int(args.case_timeout),
        "agent_context": args.agent_context,
        "noise_level": str(getattr(args, "noise_level", "none")),
        "noise_activity": getattr(args, "noise_activity", None),
        "noise_activity_config": noise_activity_config(args),
        "model": args.model,
        "agent_runner": args.agent_runner,
        "reuse_scenarios_from": str(getattr(args, "reuse_scenarios_from", "")),
    }
    if any(options.get(key, "enterprise_3tier" if key == "template" else None) != value
           for key, value in expected.items()):
        return False
    if state.get("selected_case_ids") != [str(case["id"]) for case in selected]:
        return False
    for case in selected:
        item = (state.get("cases") or {}).get(str(case["id"]))
        if not isinstance(item, dict) or list((item.get("case") or {}).get("cves") or []) != list(case.get("cves") or []):
            return False
        scenario_dir = Path(str(item.get("scenario_dir") or ""))
        if any(not (scenario_dir / name).is_file() for name in ("scenario.yaml", "ground_truth.json", "clab.yaml")):
            return False
    return True


def summarize(case: dict[str, object], scenario_dir: Path, result: dict) -> dict:
    agent_result = result.get("agent_result") or {}
    raw_context = result.get("agent_context")
    raw_profile = result.get("agent_exposure_profile")
    if raw_context is None and isinstance(raw_profile, dict):
        raw_context = raw_profile.get("context")
    context = normalize_agent_context(raw_context or "guided")
    profile = normalize_agent_exposure_profile(raw_profile, context=context)
    return {
        "case_id": case["id"],
        "purpose": case["purpose"],
        "cves": case["cves"],
        "asset_variants": case.get("asset_variants", {}),
        "resolved_asset_bindings": result.get("resolved_asset_bindings", {}),
        "scenario_dir": str(scenario_dir),
        "agent_context": context,
        "agent_exposure_profile": profile.model_dump(mode="json"),
        "requested_agent_context": result.get("requested_agent_context", ""),
        "requested_agent_exposure_profile": result.get(
            "requested_agent_exposure_profile", {}
        ),
        "success": bool(result.get("success", False)),
        "environment_verified": bool(result.get("environment_verified", False)),
        "environment_success": bool(result.get("environment_success", False)),
        "range_build_verified": bool(result.get("range_build_verified", False)),
        "attack_graph_valid": bool(result.get("attack_graph_valid", False)),
        "attack_path_reachable": bool(result.get("attack_path_reachable", False)),
        "guided_trial_evaluated": bool(result.get("guided_trial_evaluated", False)),
        "guided_trial_success": bool(result.get("guided_trial_success", False)),
        "objective_achieved": bool(result.get("objective_achieved", False)),
        "agent_evaluated": bool(
            result.get("agent_evaluated", result.get("guided_trial_evaluated", False))
        ),
        "agent_success": bool(result.get("agent_success", False)),
        "failure_stage": result.get("failure_stage", ""),
        "guide_integrity_valid": bool(
            (result.get("guide_integrity", {}) or {}).get("valid", True)
        ),
        "guide_advisory_status": (
            result.get("guide_advisories", result.get("guide_compatibility", {}))
            or {}
        ).get("overall_status", ""),
        "guide_compatibility_status": (
            result.get("guide_advisories", result.get("guide_compatibility", {})) or {}
        ).get("overall_status", ""),
        "agent_termination_reason": result.get("agent_termination_reason", ""),
        "batch_fingerprint": result.get("batch_fingerprint", "")
        or (result.get("validation_round") or {}).get("batch_fingerprint", ""),
        "hint_profile": result.get("hint_profile", ""),
        "prompt_hygiene": result.get("prompt_hygiene", {}),
        "material_audit": (
            agent_result.get("material_audit") or result.get("material_audit", {})
        ),
        "agent_structured_result": bool(agent_result.get("structured_result", False)),
        "agent_partial_result": bool(agent_result.get("partial_result", False)),
        "observed_progress": agent_result.get("observed_progress", {}),
        "agent_runner_diagnostic": agent_result.get("runner_diagnostic", {}),
        "decoy_interactions": result.get("decoy_interactions", {}),
        "noise_activity": result.get("noise_activity", {}),
        "noise_activity_config": result.get("noise_activity_config", {}),
        "noise_profile_coverage": result.get("noise_profile_coverage", []),
        "noise_profile_admission": result.get("noise_profile_admission", {}),
        "entry_discovery_preflight": result.get("entry_discovery_preflight", {}),
        "sysarmor": result.get("sysarmor", {}),
        "error": result.get("error", ""),
    }


def _agent_attempt_evaluated(result: dict[str, Any]) -> bool:
    """Whether an Agent trial already consumed research/API resources."""
    if result.get("agent_termination_reason") in {
        "prompt_hygiene", "agent_exposure_profile_mismatch",
    }:
        return False
    hygiene = result.get("prompt_hygiene")
    if isinstance(hygiene, dict) and hygiene.get("profile") == "not_evaluated":
        return False
    return bool(result.get("agent_evaluated") or result.get("guided_trial_evaluated"))


def _should_retry(result: dict[str, Any], attempts: int, interrupted: bool) -> bool:
    """Retry only pre-Agent infrastructure failures."""
    infra_failure = (
        result.get("failure_stage") in INFRA_RETRY_STAGES
        or bool(result.get("cleanup_failed", False))
    )
    return bool(
        infra_failure
        and attempts < 2
        and not _agent_attempt_evaluated(result)
        and not interrupted
    )


def _digest_inputs(selected: list[dict[str, object]], args: argparse.Namespace) -> str:
    """Fingerprint experiment inputs without storing API credentials."""
    digest = hashlib.sha256()
    digest.update(json.dumps(selected, sort_keys=True, ensure_ascii=False).encode())
    context = normalize_agent_context(getattr(args, "agent_context", "guided"))
    profile = AgentExposureProfile.from_context(context).model_dump(mode="json")
    digest.update(json.dumps({
        "templates_dir": args.templates_dir, "atoms_dir": args.atoms_dir,
        "template": str(getattr(args, "template", "enterprise_3tier")),
        "max_turns": args.max_turns, "agent_timeout": args.agent_timeout,
        "environment_only": args.environment_only, "generate_only": args.generate_only,
        "validation_mode": "guided_agent",
        "agent_context": context,
        "agent_exposure_profile": profile,
        "noise_level": str(getattr(args, "noise_level", "none")),
        "noise_activity": getattr(args, "noise_activity", None),
        "noise_activity_config": noise_activity_config(args),
        "reuse_scenarios_from": str(getattr(args, "reuse_scenarios_from", "")),
        "agent_runner": args.agent_runner,
        "model": args.model,
        "base_url": args.base_url,
        "llm_temperature": os.environ.get("LLM_TEMPERATURE", ""),
        "max_tokens": os.environ.get("MAX_TOKENS", os.environ.get("LLM_MAX_TOKENS", "")),
        "sysarmor": bool(getattr(args, "sysarmor", False)),
        "sysarmor_detection": bool(getattr(args, "sysarmor_detection", False)),
        "sysarmor_signal_window": int(getattr(args, "sysarmor_signal_window", 30)),
        "seed": getattr(args, "seed", None),
        "parallel": int(getattr(args, "parallel", 0)),
        "case_timeout": int(getattr(args, "case_timeout", 0)),
    }, sort_keys=True).encode())
    paths = [Path(__file__),
             ROOT / "data" / "atom_pool_status.json",
             ROOT / "data" / "range_matrix_status.json",
             ROOT / "src/clab_builder/orchestrator/composer/verifier.py",
             ROOT / "src/clab_builder/orchestrator/composer/scenario.py",
             ROOT / "src/clab_builder/orchestrator/composer/scenario_assembler.py",
             ROOT / "src/clab_builder/orchestrator/noise",
             ROOT / "src/clab_builder/orchestrator/composer/scenario_runner.py",
             ROOT / "src/clab_builder/orchestrator/composer/openai_scenario_runner.py",
             ROOT / "src/clab_builder/orchestrator/composer/sysfield_exporter.py",
             ROOT / "src/clab_builder/shared/models/artifact_contracts.py",
             ROOT / "src/clab_builder/shared/source_bundle.py",
             ROOT / "src/clab_builder/shared/atom_pool_status.py",
             ROOT / args.templates_dir]
    if args.case_manifest:
        case_manifest = Path(args.case_manifest)
        paths.append(case_manifest if case_manifest.is_absolute() else ROOT / case_manifest)
    for case in selected:
        for cve in case["cves"]:
            atom_dir = ROOT / args.atoms_dir / str(cve)
            paths.extend([
                atom_dir / "atom.yaml",
                atom_dir / "exploit_guide.yaml",
                atom_dir / "source_bundle",
                atom_dir / "runtime",
            ])

    def update_path(path: Path) -> None:
        try:
            label = path.resolve().relative_to(ROOT.resolve()).as_posix()
        except ValueError:
            label = str(path.resolve())
        digest.update(label.encode())
        if path.is_file():
            digest.update(path.read_bytes())
            return
        if path.is_dir():
            files = sorted(item for item in path.rglob("*") if item.is_file())
            for item in files:
                update_path(item)
            return
        digest.update(b"<missing>")

    for path in paths:
        update_path(path)
    return digest.hexdigest()


def _docker_json(command: list[str]) -> Any | None:
    result = subprocess.run(command, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _docker_network_subnets() -> set[ipaddress.IPv4Network]:
    listed = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.ID}}"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    subnets: set[ipaddress.IPv4Network] = set()
    if listed.returncode != 0:
        return subnets
    for network_id in listed.stdout.splitlines():
        inspected = _docker_json(["docker", "network", "inspect", network_id])
        for item in inspected or []:
            for config in ((item.get("IPAM") or {}).get("Config") or []):
                try:
                    subnet = config.get("Subnet")
                    if subnet:
                        subnets.add(ipaddress.ip_network(subnet, strict=False))
                except ValueError:
                    continue
    return subnets


def select_management_network() -> dict[str, str]:
    existing = _docker_json(["docker", "network", "inspect", MGMT_NETWORK_NAME])
    if isinstance(existing, list) and existing:
        item = existing[0]
        config = ((item.get("IPAM") or {}).get("Config") or [{}])[0]
        subnet = str(config.get("Subnet") or "")
        if item.get("Driver") != "bridge" or subnet not in MGMT_SUBNETS:
            raise RuntimeError(
                f"existing {MGMT_NETWORK_NAME} is not a supported bridge /24: {subnet or 'unknown'}"
            )
        return {
            "name": MGMT_NETWORK_NAME, "subnet": subnet,
            "endpoints": str(len(item.get("Containers") or {})),
        }
    occupied = _docker_network_subnets()
    for candidate in MGMT_SUBNETS:
        network = ipaddress.ip_network(candidate)
        if not any(network.overlaps(item) for item in occupied):
            return {"name": MGMT_NETWORK_NAME, "subnet": candidate, "endpoints": "0"}
    raise RuntimeError("no non-overlapping /24 is available for the shared ContainerLab management network")


def control_lease(run_id: str, case_id: str, reserved_subnets: list[str]) -> dict[str, str]:
    """Reserve a per-case Agent bridge in the parent, before worker launch."""
    occupied = _docker_network_subnets()
    reserved = []
    for item in reserved_subnets:
        try:
            reserved.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    case_digest = hashlib.sha256(case_id.encode()).hexdigest()[:12]
    network_name = f"cvelab-agent-{run_id[:8]}-{case_digest}-{secrets.token_hex(3)}"
    for candidate in CONTROL_SUBNETS:
        network = ipaddress.ip_network(candidate)
        if any(network.overlaps(item) for item in [*occupied, *reserved]):
            continue
        gateway = str(next(network.hosts()))
        created = subprocess.run([
            "docker", "network", "create", "--driver", "bridge", "--subnet", candidate,
            "--gateway", gateway, "--opt", "com.docker.network.container_iface_prefix=ctl",
            "--label", "cvelab.role=agent-control", "--label", f"cvelab.run={run_id}",
            "--label", f"cvelab.case={case_id}", network_name,
        ], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if created.returncode == 0:
            return {"network_name": network_name, "subnet": candidate, "gateway": gateway}
    raise RuntimeError("no disjoint Agent control subnet lease is available")


def release_control_lease(lease: dict[str, Any] | None) -> dict[str, Any]:
    """Disconnect every endpoint and remove one known Agent-control network.

    A coordinator can be interrupted after the Agent container is gone but
    before Docker removes the bridge.  ``docker network rm`` then fails with
    ``active endpoints``; silently ignoring that failure was the source of
    residual per-case networks.  The lease is narrowly scoped by name, so it
    is safe to disconnect all endpoints found on this one network.
    """
    network = str((lease or {}).get("network_name") or "")
    if not network:
        return {"ok": True, "skipped": True}

    def _missing(output: str) -> bool:
        lowered = output.lower()
        return ("no such network" in lowered
                or ("network" in lowered and "not found" in lowered))

    errors: list[str] = []
    disconnected: list[str] = []
    for _attempt in range(2):
        inspected = subprocess.run(
            ["docker", "network", "inspect", network],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        if inspected.returncode != 0:
            output = f"{inspected.stdout}\n{inspected.stderr}".strip()
            if _missing(output):
                return {"ok": True, "network_name": network, "already_absent": True}
            errors.append(output[-1000:] or "network inspect failed")
            return {"ok": False, "network_name": network, "errors": errors}
        try:
            inspected_data = json.loads(inspected.stdout)
            containers = (inspected_data[0].get("Containers") or {}) if inspected_data else {}
        except (json.JSONDecodeError, IndexError, AttributeError, TypeError) as exc:
            return {
                "ok": False, "network_name": network,
                "errors": [f"network inspect parse failed: {exc}"],
            }

        for container_id in containers:
            disconnected_result = subprocess.run(
                ["docker", "network", "disconnect", "-f", network, str(container_id)],
                capture_output=True, text=True, stdin=subprocess.DEVNULL,
            )
            output = f"{disconnected_result.stdout}\n{disconnected_result.stderr}".strip()
            if disconnected_result.returncode == 0:
                disconnected.append(str(container_id))
            elif not (
                "not connected" in output.lower()
                or "no such container" in output.lower()
                or _missing(output)
            ):
                errors.append(output[-1000:] or "network disconnect failed")

        removed = subprocess.run(
            ["docker", "network", "rm", network],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        output = f"{removed.stdout}\n{removed.stderr}".strip()
        if removed.returncode == 0 or _missing(output):
            return {
                "ok": True, "network_name": network,
                "disconnected": disconnected,
                "errors": errors,
            }
        if output:
            errors.append(output[-1000:])

    return {
        "ok": False, "network_name": network,
        "disconnected": disconnected,
        "errors": errors or ["network rm failed"],
    }


def _runner_base_url(agent_runner: str, base_url: str) -> str:
    value = str(base_url or "").rstrip("/")
    if agent_runner == "openai" and value.endswith("/anthropic"):
        return value[: -len("/anthropic")]
    return base_url


def scenario_reserved_subnets(scenario_dir: Path) -> list[str]:
    try:
        import yaml
        data = load_scenario_manifest(
            yaml.safe_load((scenario_dir / "scenario.yaml").read_text()) or {}
        ).model_dump(mode="json", exclude_none=True)
        return [str(item) for item in data.get("network_subnets") or []]
    except Exception:
        return []


def lab_lock(path: Path):
    class _Lock:
        def __enter__(self_inner):
            path.parent.mkdir(parents=True, exist_ok=True)
            self_inner.handle = path.open("a+")
            if fcntl is None:
                return self_inner
            try:
                fcntl.flock(self_inner.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                self_inner.handle.close()
                raise RuntimeError("scheduler_conflict") from exc
            return self_inner

        def __exit__(self_inner, *_exc):
            if fcntl is not None:
                fcntl.flock(self_inner.handle.fileno(), fcntl.LOCK_UN)
            self_inner.handle.close()
    return _Lock()


def _proc_start_ticks(pid: int) -> str:
    """Return Linux process start ticks for PID, or an empty string."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        # ``comm`` (field 2) may contain spaces; split only after its closing
        # parenthesis.  The remaining list starts at field 3, so field 22
        # (starttime) is index 19.
        fields = stat.rsplit(")", 1)[1].split()
        return str(fields[19])
    except (OSError, IndexError):
        return ""


def _find_worker_pid(worker_spec_path: str) -> int | None:
    """Find a worker during the launch window before its PID was persisted."""
    target = str(Path(worker_spec_path).resolve()) if worker_spec_path else ""
    if not target:
        return None
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(entry.name)
            command_line = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                errors="replace"
            )
        except (OSError, ValueError):
            continue
        if (
            "verify_enterprise3_guided_batch.py" in command_line
            and "--worker-spec" in command_line
            and target in command_line
        ):
            return pid
    return None


def _process_group_exists(pgid: int) -> bool:
    if pgid <= 1:
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # ``killpg(..., 0)`` also succeeds while the group contains only zombie
    # processes.  A worker leader can briefly be a zombie until the original
    # coordinator reaps its Popen handle; zombies cannot execute Docker work
    # or publish a result, so they must not keep cleanup in a false failure
    # state.  Inspect the process-group field and count only live members.
    for entry in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = entry.read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            state = fields[0]
            process_group = int(fields[2])
        except (OSError, ValueError, IndexError):
            continue
        if process_group == pgid and state not in {"Z", "X"}:
            return True
    return False


def _wait_process_group_exit(pgid: int, timeout: float) -> bool:
    """Wait until a worker process group has no remaining members."""
    deadline = time.monotonic() + max(0.0, timeout)
    while _process_group_exists(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def _terminate_process_group(
    pid: int,
    pgid: int | None = None,
    *,
    first_signal: signal.Signals = signal.SIGTERM,
    grace_seconds: float = 30.0,
    kill_grace_seconds: float = 5.0,
) -> dict[str, Any]:
    """Stop a worker and wait for its entire process group, not only its PID."""
    group = int(pgid or pid)
    if not _process_group_exists(group):
        return {"ok": True, "pgid": group, "already_absent": True}
    try:
        os.killpg(group, first_signal)
    except ProcessLookupError:
        return {"ok": True, "pgid": group, "already_absent": True}
    if _wait_process_group_exit(group, grace_seconds):
        return {"ok": True, "pgid": group, "signal": first_signal.name}
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        return {"ok": True, "pgid": group, "forced": True}
    gone = _wait_process_group_exit(group, kill_grace_seconds)
    return {
        "ok": gone,
        "pgid": group,
        "signal": first_signal.name,
        "forced": True,
        "error": "worker process group did not exit" if not gone else "",
    }


def _attempt_result_path(case_state: dict[str, Any]) -> Path:
    """Return the attempt-isolated result path, with legacy fallback."""
    return Path(case_state.get("worker_result_path") or case_state["result_path"])


def _revoke_attempt_fence(case_state: dict[str, Any]) -> None:
    case_state["attempt_fence_revoked_at_ns"] = time.time_ns()
    fence = str(case_state.get("attempt_fence_path") or "")
    if not fence:
        return
    try:
        Path(fence).unlink(missing_ok=True)
    except OSError:
        pass


def _attempt_fence_is_valid(spec: dict[str, Any]) -> bool:
    """Check that this worker still owns the attempt before writing results."""
    fence_path = str(spec.get("attempt_fence_path") or "")
    token = str(spec.get("attempt_token") or "")
    if not fence_path or not token:
        # Legacy worker specs predate result fencing; new launches always set
        # both fields.  Keeping this fallback makes old cleanup-only specs
        # readable without weakening new attempts.
        return not fence_path and not token
    try:
        payload = json.loads(Path(fence_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if payload.get("token") != token:
        return False
    if payload.get("run_id") != spec.get("run_id"):
        return False
    if payload.get("case_id") != spec.get("case", {}).get("id"):
        return False
    if int(payload.get("attempt", -1)) != int(spec.get("attempt", -2)):
        return False
    coordinator_pid = int(payload.get("coordinator_pid") or 0)
    if coordinator_pid:
        if os.getppid() != coordinator_pid:
            return False
        expected_ticks = str(payload.get("coordinator_start_ticks") or "")
        if expected_ticks and _proc_start_ticks(coordinator_pid) != expected_ticks:
            return False
    return True


def _write_worker_result(spec: dict[str, Any], result: dict[str, Any]) -> int:
    """Write only to the attempt file while its coordinator fence is valid."""
    if not _attempt_fence_is_valid(spec):
        print("[Worker] result fence revoked; discarding late result", flush=True)
        return 125
    payload = dict(result)
    payload["worker_attempt"] = {
        "run_id": spec.get("run_id", ""),
        "case_id": spec.get("case", {}).get("id", ""),
        "attempt": int(spec.get("attempt", 0) or 0),
    }
    atomic_json(Path(spec.get("worker_result_path") or spec["result_path"]), payload)
    return 0


def _load_attempt_result(case_state: dict[str, Any]) -> dict[str, Any] | None:
    """Load a result only if it belongs to the current run/case/attempt."""
    path = _attempt_result_path(case_state)
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    revoked_at_ns = int(case_state.get("attempt_fence_revoked_at_ns") or 0)
    if revoked_at_ns:
        try:
            if path.stat().st_mtime_ns > revoked_at_ns:
                return None
        except OSError:
            return None
    marker = result.get("worker_attempt")
    if case_state.get("worker_result_path"):
        if not isinstance(marker, dict):
            return None
        if marker.get("case_id") != case_state.get("case", {}).get("id"):
            return None
        if int(marker.get("attempt", -1)) != int(case_state.get("attempts", -2)):
            return None
    return result


def run_worker(spec_path: Path) -> int:
    """Hidden worker entrypoint; spec contains no secret/API key."""
    spec = json.loads(spec_path.read_text())
    started = utcnow()
    context = normalize_agent_context(spec.get("agent_context", "guided"))
    profile = normalize_agent_exposure_profile(
        spec.get("agent_exposure_profile"), context=context
    )
    try:
        if load_dotenv is not None:
            load_dotenv(ROOT / ".env")
        with lab_lock(Path(spec["lab_lock_path"])):
            verifier = ScenarioVerifier(
                max_turns=int(spec["max_turns"]), agent_timeout=int(spec["agent_timeout"]),
                require_agent_success=not bool(spec["environment_only"]),
                atoms_dir=str(spec["atoms_dir"]), validation_mode="guided_agent",
                strict_guide_compatibility=bool(spec["strict_guide_compatibility"]),
            )
            raw = verifier.run_full(
                scenario_dir=str(spec["scenario_dir"]),
                api_key=os.getenv("LLM_API_KEY", ""), base_url=os.getenv("LLM_BASE_URL", ""),
                model=os.getenv("LLM_MODEL", ""), environment_only=bool(spec["environment_only"]),
                runtime_policy="verify_only", execution_context={
                    "run_id": spec["run_id"], "case_id": spec["case"]["id"],
                    "worker_id": spec["worker_id"], "lab_name": spec["lab_name"],
                    "seed": spec.get("seed", 0),
                    "ansible_paths": spec["ansible_paths"], "mgmt_network": spec.get("mgmt_network") or {},
                    "control_network_lease": spec.get("control_network_lease") or {},
                    "noise_level": spec.get("noise_level", "none"),
                    "noise_activity": spec.get("noise_activity"),
                    "noise_activity_config": spec.get("noise_activity_config", {}),
                    "batch_fingerprint": spec.get("batch_fingerprint", ""),
                },
                agent_context=context,
                agent_runner=str(spec.get("agent_runner", "claude")),
                sysarmor=spec.get("sysarmor") or {},
            )
            # run_full writes final cleanup information in its ``finally``
            # block.  Reload it so the batch result records that durable
            # lifecycle outcome rather than the pre-cleanup return snapshot.
            persisted_path = Path(spec["scenario_dir"]) / "verify_result.json"
            if persisted_path.exists():
                try:
                    raw = load_verification_result(
                        json.loads(persisted_path.read_text())
                    ).model_dump(mode="json", exclude_none=True)
                except json.JSONDecodeError:
                    pass
            result = summarize(spec["case"], Path(spec["scenario_dir"]), raw)
            result["execution_complete"] = bool(raw.get("execution_complete", False))
            result["cleanup_failed"] = not result["execution_complete"]
            result["lifecycle"] = {
                "run_id": spec["run_id"], "lab_name": spec["lab_name"],
                "worker_id": spec["worker_id"], "started_at": started, "finished_at": utcnow(),
                "cleanup": raw.get("cleanup", {}),
            }
    except RuntimeError as exc:
        stage = "scheduler_conflict" if str(exc) == "scheduler_conflict" else "worker_failed"
        result = {"case_id": spec["case"]["id"], "purpose": spec["case"]["purpose"],
                  "cves": spec["case"]["cves"], "scenario_dir": str(spec["scenario_dir"]),
                  "agent_context": context,
                  "agent_exposure_profile": profile.model_dump(mode="json"),
                  "success": False, "failure_stage": stage, "error": repr(exc),
                  "execution_complete": False}
    except Exception as exc:
        result = {"case_id": spec["case"]["id"], "purpose": spec["case"]["purpose"],
                  "cves": spec["case"]["cves"], "scenario_dir": str(spec["scenario_dir"]),
                  "agent_context": context,
                  "agent_exposure_profile": profile.model_dump(mode="json"),
                  "success": False, "failure_stage": "worker_failed", "error": repr(exc),
                  "execution_complete": False}
    return _write_worker_result(spec, result)


def _write_summary(output_dir: Path, state: dict[str, Any]) -> None:
    ordered = []
    for case_id in state["selected_case_ids"]:
        case_state = state["cases"][case_id]
        result_path = Path(case_state["result_path"])
        if result_path.exists():
            try:
                ordered.append(json.loads(result_path.read_text()))
            except json.JSONDecodeError:
                pass
    context = normalize_agent_context(state["options"].get("agent_context", "guided"))
    profile = normalize_agent_exposure_profile(
        state["options"].get("agent_exposure_profile"), context=context
    )
    summary = {
        "schema_version": 1,
        "created_at": utcnow(), "run_id": state["run_id"],
        "template": state["options"].get("template", "enterprise_3tier"),
        "validation_mode": "guided_agent", "environment_only": state["options"]["environment_only"],
        "agent_context": context,
        "agent_exposure_profile": profile.model_dump(mode="json"),
        "noise_level": state["options"].get("noise_level", "none"),
        "noise_activity": state["options"].get("noise_activity"),
        "noise_activity_config": state["options"].get("noise_activity_config", {}),
        "scenario_reuse": state.get("scenario_reuse", {}),
        "parallel_history": state.get("parallel_history", []),
        "model": state["options"].get("model", ""),
        "agent_runner": state["options"].get("agent_runner", "claude"),
        # Top-level validation-round tag: identifies which batch this summary
        # belongs to so downstream level/agent experiments can reuse a set of
        # Ranges with a traceable "validated in round X" provenance. Each
        # per-scenario verify_result.json also carries its own validation_round.
        "validation_round": {
            "run_id": state["run_id"],
            "template": state["options"].get("template", "enterprise_3tier"),
            "agent_context": context,
            "agent_exposure_profile": profile.model_dump(mode="json"),
            "noise_level": state["options"].get("noise_level", "none"),
            "noise_activity": state["options"].get("noise_activity"),
            "noise_activity_config": state["options"].get("noise_activity_config", {}),
            "scenario_reuse": state.get("scenario_reuse", {}),
            "parallel_history": state.get("parallel_history", []),
            "model": state["options"].get("model", ""),
            "agent_runner": state["options"].get("agent_runner", "claude"),
            "environment_only": state["options"]["environment_only"],
            "max_turns": state["options"].get("max_turns"),
            "agent_timeout": state["options"].get("agent_timeout"),
            "seed": state["options"].get("seed"),
            "case_timeout": state["options"].get("case_timeout"),
            "created_at": state.get("created_at", utcnow()),
        },
        "selected_cases": state["selected_case_ids"], "results": ordered,
        "case_states": {key: value["status"] for key, value in state["cases"].items()},
        "fingerprint": state["fingerprint"],
    }
    atomic_json(output_dir / "summary.json", normalize_batch_summary(summary))


def _persist(output_dir: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = utcnow()
    existing_cases = state.get("cases")
    normalized = normalize_batch_state(state)
    # Keep case-dict identity stable across persistence.  The coordinator and
    # cleanup loops hold short-lived references to case entries; replacing
    # every nested dict here makes those references stale immediately after a
    # write, which can drop worker PID/PGID updates from durable state.
    if isinstance(existing_cases, dict) and isinstance(normalized.get("cases"), dict):
        for case_id, normalized_case in normalized["cases"].items():
            current_case = existing_cases.get(case_id)
            if isinstance(current_case, dict):
                current_case.clear()
                current_case.update(normalized_case)
            else:
                existing_cases[case_id] = normalized_case
        normalized["cases"] = existing_cases
    state.clear()
    state.update(normalized)
    atomic_json(output_dir / "batch_state.json", state)
    _write_summary(output_dir, state)


def _result_for_infra(case_state: dict[str, Any], stage: str, error: str) -> dict[str, Any]:
    case = case_state["case"]
    context = normalize_agent_context(case_state.get("agent_context", "guided"))
    profile = normalize_agent_exposure_profile(
        case_state.get("agent_exposure_profile"), context=context
    )
    return {
        "case_id": case["id"], "purpose": case["purpose"], "cves": case["cves"],
        "scenario_dir": case_state["scenario_dir"], "success": False,
        "agent_context": context,
        "agent_exposure_profile": profile.model_dump(mode="json"),
        "failure_stage": stage, "error": error, "execution_complete": False,
    }


def _save_case_result(case_state: dict[str, Any], result: dict[str, Any]) -> None:
    atomic_json(Path(case_state["result_path"]), result)


def _current_attempt_record(case_state: dict[str, Any]) -> dict[str, Any]:
    """Return a mutable current-attempt record, repairing legacy state.

    Older or interrupted batch states can contain a running/cleaning case
    without ``attempt_records``. Cleanup must preserve the failure evidence,
    not crash while trying to annotate that missing history.
    """
    records = case_state.get("attempt_records")
    if not isinstance(records, list):
        records = []
        case_state["attempt_records"] = records
    if not records or not isinstance(records[-1], dict):
        records.append({
            "attempt": int(case_state.get("attempts", 0) or 0),
            "started_at": "",
            "log_path": "",
        })
    return records[-1]


def _update_current_attempt_record(case_state: dict[str, Any], **updates: Any) -> None:
    _current_attempt_record(case_state).update(updates)


def _generate_one_case(payload: dict[str, Any]) -> dict[str, Any]:
    """Generate one isolated scenario in a worker process.

    Scenario generation is independent per case, but it is CPU-heavy enough
    that threads do not provide useful parallelism.  The worker constructs its
    own Pipeline so template/Atom caches and Python's random state cannot be
    shared across cases.
    """
    try:
        pipeline = ScenarioPipeline(
            templates_dir=payload["templates_dir"],
            atoms_dir=payload["atoms_dir"],
            default_validation_mode="guided_agent",
        )
        pipeline.generate(
            template_name=payload.get("template", "enterprise_3tier"),
            cve_ids=list(payload["cves"]),
            scenario_name=payload["lab_name"],
            output_dir=payload["scenarios_root"],
            seed=payload["seed"],
            validation_mode="guided_agent",
            agent_context=payload["agent_context"],
            noise_level=payload["noise_level"],
            noise_activity=payload["noise_activity"],
            noise_activity_config=payload["noise_activity_config"],
        )
        if payload["sysarmor_detection"] and payload["environment_only"]:
            SysFieldExporter(atoms_dir=payload["atoms_dir"]).export(
                str(Path(payload["scenarios_root"]) / payload["lab_name"])
            )
        return {"ok": True, "scenario_dir": str(Path(payload["scenarios_root"]) / payload["lab_name"])}
    except Exception as exc:
        return {"ok": False, "failure_stage": "generation", "error": repr(exc)}


def _generate_cases(state: dict[str, Any], args: argparse.Namespace, output_dir: Path) -> None:
    scenarios_root = output_dir / "scenarios"
    pending = [
        state["cases"][case_id]
        for case_id in state["selected_case_ids"]
        if state["cases"][case_id]["status"] in {"pending", "generation_failed"}
    ]
    if not pending:
        return
    worker_count = max(1, min(int(getattr(args, "parallel", 1)), len(pending)))
    common = {
        "templates_dir": args.templates_dir,
        "atoms_dir": args.atoms_dir,
        "template": str(getattr(args, "template", "enterprise_3tier")),
        "scenarios_root": str(scenarios_root),
        "seed": args.seed,
        "agent_context": str(getattr(args, "agent_context", "guided")),
        "noise_level": str(getattr(args, "noise_level", "none")),
        "noise_activity": getattr(args, "noise_activity", None),
        "noise_activity_config": noise_activity_config(args),
        "sysarmor_detection": bool(getattr(args, "sysarmor_detection", False)),
        "environment_only": bool(getattr(args, "environment_only", False)),
    }
    payloads = {
        item["case"]["id"]: {
            **common,
            "cves": list(item["case"]["cves"]),
            "lab_name": item["lab_name"],
        }
        for item in pending
    }
    with ProcessPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_generate_one_case, payload): case_id
            for case_id, payload in payloads.items()
        }
        for future in as_completed(futures):
            case_id = futures[future]
            item = state["cases"][case_id]
            outcome = future.result()
            if outcome.get("ok"):
                item["status"] = "generated"
                item["scenario_dir"] = outcome["scenario_dir"]
            else:
                item["status"] = "completed"
                _save_case_result(
                    item,
                    _result_for_infra(
                        item, outcome.get("failure_stage", "generation"), outcome.get("error", "")
                    ),
                )
            _persist(output_dir, state)


def _prewarm_cases(state: dict[str, Any], args: argparse.Namespace, output_dir: Path) -> None:
    verifier = ScenarioVerifier(atoms_dir=args.atoms_dir, validation_mode="guided_agent")
    prepared: dict[str, dict[str, Any]] = {}
    for case_id in state["selected_case_ids"]:
        item = state["cases"][case_id]
        if item["status"] != "generated":
            continue
        scenario_dir = Path(item["scenario_dir"])
        try:
            import yaml
            meta = load_scenario_manifest(
                yaml.safe_load((scenario_dir / "scenario.yaml").read_text()) or {}
            ).model_dump(mode="json", exclude_none=True)
            images = meta.get("runtime_images") or []
            key = hashlib.sha256(json.dumps(images, sort_keys=True).encode()).hexdigest()
            if key in prepared:
                prior = prepared[key]
                check = {**prior, "action": "deduplicated", "source_check": prior.get("action", "prewarm")}
            else:
                check = verifier.prepare_runtime_images(
                    str(scenario_dir), runtime_policy="verify_only"
                )
                prepared[key] = check
            if not check.get("ok"):
                item["status"] = "completed"
                _save_case_result(item, _result_for_infra(item, "runtime_materialization", json.dumps(check, ensure_ascii=False)))
            else:
                item["status"] = "runtime_prepared"
                item["runtime_preparation"] = check
        except Exception as exc:
            item["status"] = "completed"
            _save_case_result(item, _result_for_infra(item, "runtime_materialization", repr(exc)))
        _persist(output_dir, state)


def _complete_generate_only_preflight(
    state: dict[str, Any],
    args: argparse.Namespace,
    output_dir: Path,
    agent_exposure_profile: dict[str, Any],
) -> bool:
    """Finish a no-deploy batch only after runtime materialization preflight.

    ``--generate-only`` is the user-facing no-Agent readiness gate.  It must
    not report a generated Range as successful when its selected runtime image
    is missing or has drifted from the Atom handoff contract.
    """
    _prewarm_cases(state, args, output_dir)
    all_preflighted = True
    strict_normal = getattr(args, "noise_activity", None) == "normal"
    for case_id in state["selected_case_ids"]:
        item = state["cases"][case_id]
        if item["status"] != "runtime_prepared":
            all_preflighted = False
            continue
        scenario_dir = Path(item["scenario_dir"])
        try:
            ground_truth = load_ground_truth(
                json.loads((scenario_dir / "ground_truth.json").read_text())
            ).model_dump(mode="json")
            coverage = list(ground_truth.get("noise_profile_coverage") or [])
            admission = dict(ground_truth.get("noise_profile_admission") or {})
            fallback_profiles = [
                row for row in coverage
                if row.get("profile_id") == "tcp-generic" or row.get("status") == "fallback"
            ]
            manifest = load_scenario_manifest(
                __import__("yaml").safe_load((scenario_dir / "scenario.yaml").read_text()) or {}
            ).model_dump(mode="json")
            atom_images = {
                str(item.get(key, "")).split("@", 1)[0]
                for item in manifest.get("injections", [])
                for key in ("source_image", "runtime_image")
                if item.get(key)
            }
            noise_images = {
                str(item.get("image", "")).split("@", 1)[0]
                for item in ground_truth.get("noise_nodes", [])
                if item.get("image")
            }
            reused_images = sorted(atom_images & noise_images)
            public_text = (scenario_dir / "scenario.yaml").read_text()
            target_leak = "NOISE_TARGETS" in public_text or "targets:" in public_text
            entry_gate = {
                "evaluated": args.agent_context == "l1_entry_discovery",
                "ok": True,
                "entry_points": [],
            }
            if args.agent_context == "l1_entry_discovery":
                try:
                    entry_points = build_entry_discovery_points(
                        ground_truth,
                        manifest.get("ip_allocations") or {},
                        case_key=case_id,
                        seed=args.seed,
                    )
                    real_entry_points = build_entry_discovery_points(
                        {**ground_truth, "noise_nodes": []},
                        manifest.get("ip_allocations") or {},
                        case_key=case_id,
                        seed=args.seed,
                    )
                    decoy_entry_points = [
                        endpoint for endpoint in entry_points
                        if endpoint not in set(real_entry_points)
                    ]
                    entry_gate["entry_points"] = entry_points
                    entry_gate["real_entry_points"] = real_entry_points
                    entry_gate["first_layer_decoy_points"] = decoy_entry_points
                    entry_gate["ok"] = bool(entry_points)
                    requested_noise_level = str(getattr(args, "noise_level", "none"))
                    if requested_noise_level == "none" and ground_truth.get("noise_nodes"):
                        entry_gate.update({
                            "ok": False,
                            "error": "none protocol fixture contains noise nodes",
                        })
                    elif requested_noise_level == "high" and not decoy_entry_points:
                        entry_gate.update({
                            "ok": False,
                            "error": "high protocol fixture has no first-layer decoy entry",
                        })
                except ValueError as exc:
                    entry_gate.update({"ok": False, "error": str(exc)})
            gate = {
                "profile_admission_eligible": admission.get("eligible"),
                "fallback_profiles": fallback_profiles,
                "vulnerable_image_reuse": reused_images,
                "agent_input_target_list_leak": target_leak,
                "entry_discovery_preflight": entry_gate,
            }
            gate_failed = bool(
                (
                    args.agent_context == "l1_entry_discovery"
                    and not entry_gate["ok"]
                )
                or (
                    strict_normal
                    and (
                        admission.get("eligible") is not True
                        or fallback_profiles
                        or reused_images
                        or target_leak
                    )
                )
            )
        except Exception as exc:
            gate = {"error": repr(exc)}
            coverage, admission = [], {}
            gate_failed = strict_normal or args.agent_context == "l1_entry_discovery"
        if gate_failed:
            all_preflighted = False
            item["status"] = "completed"
            _save_case_result(item, {
                "case_id": case_id, "purpose": item["case"]["purpose"],
                "cves": item["case"]["cves"], "scenario_dir": item["scenario_dir"],
                "generated": True, "preflight": False, "success": False,
                "failure_stage": (
                    "agent_entry_discovery_preflight"
                    if not gate.get("entry_discovery_preflight", {}).get("ok", True)
                    else "noise_profile_admission"
                ),
                "agent_context": args.agent_context,
                "agent_exposure_profile": agent_exposure_profile,
                "noise_activity_config": noise_activity_config(args),
                "noise_profile_coverage": coverage,
                "noise_profile_admission": admission,
                "entry_discovery_preflight": gate.get("entry_discovery_preflight", {}),
                "noise_profile_gate": gate,
                "execution_complete": True,
            })
            continue
        item["status"] = "completed"
        _save_case_result(item, {
            "case_id": case_id, "purpose": item["case"]["purpose"],
            "cves": item["case"]["cves"], "scenario_dir": item["scenario_dir"],
            "generated": True, "preflight": True, "success": True,
            "agent_context": args.agent_context,
            "agent_exposure_profile": agent_exposure_profile,
            "noise_level": str(getattr(args, "noise_level", "none")),
            "noise_activity": getattr(args, "noise_activity", None),
            "noise_activity_config": noise_activity_config(args),
            "noise_profile_coverage": coverage,
            "noise_profile_admission": admission,
            "entry_discovery_preflight": gate.get("entry_discovery_preflight", {}),
            "noise_profile_gate": gate,
            "sysarmor": {
                "enabled": bool(getattr(args, "sysarmor", False)),
                "detection": bool(getattr(args, "sysarmor_detection", False)),
                "signal_window": int(getattr(args, "sysarmor_signal_window", 30)),
            },
            "execution_complete": True,
        })
    _persist(output_dir, state)
    return all_preflighted


def _janitor(case_state: dict[str, Any], management: dict[str, Any]) -> dict[str, Any]:
    """Precise cleanup only for resources belonging to one known lab/lease."""
    topology = Path(case_state["scenario_dir"]) / "clab.yaml"
    if topology.exists():
        command = ["clab", "destroy", "-t", str(topology), "--cleanup"]
        if management.get("name"):
            command.append("--keep-mgmt-net")
        try:
            destroy = subprocess.run(
                command, capture_output=True, text=True, stdin=subprocess.DEVNULL,
            )
            destroy_output = f"{destroy.stdout}\n{destroy.stderr}"
            absent = "no containerlab containers found" in destroy_output.lower()
            destroy_cleanup = {
                "ok": destroy.returncode == 0 or absent,
                "returncode": destroy.returncode,
                "stdout": destroy.stdout[-1000:],
                "stderr": destroy.stderr[-1000:],
            }
        except OSError as exc:
            destroy_cleanup = {"ok": False, "stage": "destroy", "error": str(exc)}
    else:
        destroy_cleanup = {"ok": True, "skipped": True, "reason": "missing topology"}
    control_cleanup = release_control_lease(case_state.get("control_network_lease"))
    return {
        "ok": bool(destroy_cleanup.get("ok") and control_cleanup.get("ok")),
        "destroy": destroy_cleanup,
        "control_network": control_cleanup,
    }


def _terminate_recorded_worker(case_state: dict[str, Any]) -> dict[str, Any]:
    """Stop one persisted worker process group after checking ownership."""
    raw_pid = case_state.get("worker_pid")
    try:
        pid = int(raw_pid)
    except (TypeError, ValueError):
        pid = _find_worker_pid(str(case_state.get("worker_spec_path") or ""))
        if pid is None:
            return {"ok": True, "skipped": True, "reason": "missing worker pid"}
    if pid <= 1:
        return {"ok": True, "skipped": True, "reason": "invalid worker pid"}
    try:
        command_line = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
            errors="replace"
        )
    except OSError:
        command_line = ""
    expected_ticks = str(case_state.get("worker_start_ticks") or "")
    actual_ticks = _proc_start_ticks(pid)
    if expected_ticks and actual_ticks and expected_ticks != actual_ticks:
        return {"ok": False, "skipped": True, "reason": "worker pid was reused"}
    command_matches = (
        "verify_enterprise3_guided_batch.py" in command_line
        and "--worker-spec" in command_line
    )
    # New state records persist the process group explicitly.  This allows us
    # to reap a surviving child even when the worker leader has already
    # exited, while legacy state still requires the command-line ownership
    # check above.
    if not command_matches and not case_state.get("worker_pgid"):
        return {"ok": False, "skipped": True, "reason": "worker identity not confirmed"}
    return _terminate_process_group(
        pid, int(case_state.get("worker_pgid") or pid),
        first_signal=signal.SIGTERM,
    )


def _cleanup_incomplete_cases(
    state: dict[str, Any], output_dir: Path, management: dict[str, Any],
    *, case_ids: set[str] | None = None, reason: str = "interrupted",
    include_prepared: bool = False,
) -> None:
    """Make coordinator shutdown/recovery clean all known case resources."""
    targets: list[str] = []
    for case_id in state.get("selected_case_ids", []):
        if case_ids is not None and case_id not in case_ids:
            continue
        item = state["cases"][case_id]
        has_resources = (
            Path(item.get("scenario_dir", ""), "clab.yaml").exists()
            or item.get("control_network_lease")
        )
        if not include_prepared and not (
            item.get("status") in {"running", "leased", "cleaning"}
            or item.get("control_network_lease")
        ):
            continue
        if include_prepared and not has_resources:
            continue
        targets.append(case_id)

    # Revoke every attempt before stopping workers.  A worker that survives
    # the first signal can then never publish into the coordinator's canonical
    # result view.  Stop all process groups before any Docker destroy operation
    # so cleanup cannot race a still-running verifier.
    for case_id in targets:
        item = state["cases"][case_id]
        _revoke_attempt_fence(item)
        _terminate_recorded_worker(item)

    for case_id in targets:
        item = state["cases"][case_id]
        result = _load_attempt_result(item)
        cleanup = _janitor(item, management)
        if result is None:
            result = _result_for_infra(
                item, "interrupted", f"coordinator cleanup during {reason}"
            )
        result["coordinator_cleanup"] = cleanup
        if not cleanup.get("ok"):
            result["cleanup_failed"] = True
        _save_case_result(item, result)
        item.pop("worker_pid", None)
        item.pop("worker_pgid", None)
        item.pop("worker_start_ticks", None)
        item.pop("worker_spec_path", None)
        if cleanup.get("ok"):
            item["control_network_lease"] = None
            item["status"] = "runtime_prepared" if reason == "resume" else "interrupted"
        else:
            item["status"] = "cleaning"
        _update_current_attempt_record(
            item,
            finished_at=utcnow(),
            failure_stage=result.get("failure_stage", "interrupted"),
            success=bool(result.get("success", False)),
            cleanup_failed=not cleanup.get("ok"),
            cleanup=cleanup,
        )
        item["last_failure_stage"] = result.get("failure_stage", "interrupted")
        _persist(output_dir, state)


def _cleanup_run_control_networks(run_id: str) -> dict[str, Any]:
    """Sweep control networks labeled for one batch run, including unpersisted leases."""
    listed = subprocess.run(
        [
            "docker", "network", "ls",
            "--filter", "label=cvelab.role=agent-control",
            "--filter", f"label=cvelab.run={run_id}",
            "--format", "{{.Name}}",
        ],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    if listed.returncode != 0:
        return {
            "ok": False,
            "run_id": run_id,
            "errors": [listed.stderr.strip()[-1000:] or "network list failed"],
        }
    networks = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    results = [release_control_lease({"network_name": name}) for name in networks]
    return {
        "ok": all(item.get("ok") for item in results),
        "run_id": run_id,
        "networks": networks,
        "results": results,
    }


def _worker_spec(state: dict[str, Any], case_state: dict[str, Any], args: argparse.Namespace,
                 output_dir: Path, worker_id: int, management: dict[str, Any]) -> Path:
    work_dir = output_dir / ".batch" / "work" / case_state["case"]["id"]
    context = normalize_agent_context(getattr(args, "agent_context", "guided"))
    profile = AgentExposureProfile.from_context(context).model_dump(mode="json")
    spec = {
        "run_id": state["run_id"], "worker_id": str(worker_id), "case": case_state["case"],
        "template": str(getattr(args, "template", "enterprise_3tier")),
        "batch_fingerprint": state.get("fingerprint", ""),
        "lab_name": case_state["lab_name"], "scenario_dir": case_state["scenario_dir"],
        "result_path": case_state["result_path"], "lab_lock_path": str(work_dir / "lab.lock"),
        "worker_result_path": case_state.get("worker_result_path") or case_state["result_path"],
        "attempt_fence_path": case_state.get("attempt_fence_path", ""),
        "attempt_token": case_state.get("attempt_token", ""),
        "attempt": int(case_state.get("attempts", 0) or 0),
        "coordinator_pid": os.getpid(),
        "coordinator_start_ticks": _proc_start_ticks(os.getpid()),
        "atoms_dir": args.atoms_dir, "max_turns": args.max_turns, "agent_timeout": args.agent_timeout,
        "environment_only": args.environment_only,
        "agent_context": context,
        "agent_exposure_profile": profile,
        "noise_level": str(getattr(args, "noise_level", "none")),
        "noise_activity": getattr(args, "noise_activity", None),
        "noise_activity_config": noise_activity_config(args),
        "agent_runner": str(getattr(args, "agent_runner", "claude")),
        "strict_guide_compatibility": args.strict_guide_compatibility,
        "sysarmor": {
            "enabled": bool(getattr(args, "sysarmor", False)),
            "detection": bool(getattr(args, "sysarmor_detection", False)),
            "signal_window": int(getattr(args, "sysarmor_signal_window", 30)),
        },
        "mgmt_network": management, "control_network_lease": case_state.get("control_network_lease") or {},
        "ansible_paths": {
            "ANSIBLE_HOME": str(work_dir / "ansible-home"),
            "ANSIBLE_LOCAL_TEMP": str(work_dir / "ansible-local-tmp"),
            "ANSIBLE_REMOTE_TEMP": str(work_dir / "ansible-remote-tmp"),
        },
    }
    spec_path = output_dir / ".batch" / "specs" / f"{case_state['case']['id']}-a{case_state['attempts']}.json"
    atomic_json(spec_path, spec)
    return spec_path


def _stream_log_updates(
    active: dict[str, tuple[subprocess.Popen, float, Path]],
    positions: dict[str, int],
    pending: dict[str, str],
) -> None:
    """Forward complete worker-log lines without taking over log ownership."""
    for case_id, (_process, _started, log_path) in active.items():
        if not log_path.exists():
            continue
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(positions.get(case_id, 0))
                chunk = handle.read()
                positions[case_id] = handle.tell()
        except OSError:
            continue
        if not chunk:
            continue
        text = pending.get(case_id, "") + chunk
        lines = text.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            pending[case_id] = lines.pop()
        else:
            pending.pop(case_id, None)
        for line in lines:
            print(f"[{case_id}] {line.rstrip()}", flush=True)


def _launch_workers(state: dict[str, Any], args: argparse.Namespace, output_dir: Path,
                    management: dict[str, Any]) -> bool:
    """Run bounded subprocess workers; returns False only for interrupted execution."""
    active: dict[str, tuple[subprocess.Popen, float, Path]] = {}
    log_positions: dict[str, int] = {}
    log_pending: dict[str, str] = {}
    interrupted = False
    fatal_stop = False
    case_timeout = args.case_timeout or max(1800, args.agent_timeout + 1800)
    while True:
        # Keep IDs rather than dict references: _persist normalizes case
        # entries and may replace their contents while this loop is running.
        ready = [case_id for case_id in state["selected_case_ids"]
                 if state["cases"][case_id]["status"] in {"runtime_prepared", "leased"}]
        while ready and len(active) < args.parallel and not interrupted and not fatal_stop:
            case_id = ready.pop(0)
            item = state["cases"][case_id]
            if not args.environment_only and not args.generate_only and not item.get("control_network_lease"):
                try:
                    item["control_network_lease"] = control_lease(
                        state["run_id"], case_id, scenario_reserved_subnets(Path(item["scenario_dir"]))
                    )
                    item["status"] = "leased"
                    # Persist the lease before launching the worker.  If the
                    # coordinator is interrupted in the launch window, resume
                    # can still disconnect this exact network.
                    _persist(output_dir, state)
                except Exception as exc:
                    item["attempts"] += 1
                    _save_case_result(item, _result_for_infra(item, "agent_transport", repr(exc)))
                    item["status"] = "runtime_prepared" if item["attempts"] < 2 else "completed"
                    _persist(output_dir, state)
                    continue
            item["attempts"] += 1
            item["status"] = "running"
            # A retry must never consume the previous attempt's result.
            Path(item["result_path"]).unlink(missing_ok=True)
            attempt_id = int(item["attempts"])
            attempt_token = secrets.token_hex(16)
            attempt_results_dir = output_dir / ".batch" / "attempt-results"
            attempt_fences_dir = output_dir / ".batch" / "attempt-fences"
            attempt_results_dir.mkdir(parents=True, exist_ok=True)
            attempt_fences_dir.mkdir(parents=True, exist_ok=True)
            item["worker_result_path"] = str(
                attempt_results_dir / f"{case_id}-a{attempt_id}.json"
            )
            item["attempt_fence_path"] = str(
                attempt_fences_dir / f"{case_id}-a{attempt_id}.json"
            )
            item["attempt_fence_revoked_at_ns"] = None
            item["attempt_token"] = attempt_token
            Path(item["worker_result_path"]).unlink(missing_ok=True)
            atomic_json(Path(item["attempt_fence_path"]), {
                "token": attempt_token,
                "run_id": state["run_id"],
                "case_id": case_id,
                "attempt": attempt_id,
                "coordinator_pid": os.getpid(),
                "coordinator_start_ticks": _proc_start_ticks(os.getpid()),
            })
            spec_path = _worker_spec(state, item, args, output_dir, len(active) + 1, management)
            log_path = output_dir / ".batch" / "logs" / f"{case_id}-a{item['attempts']}.log"
            item.setdefault("attempt_records", []).append({
                "attempt": item["attempts"], "started_at": utcnow(), "log_path": str(log_path),
                "parallel": args.parallel,
                "worker_result_path": item["worker_result_path"],
                "attempt_fence_path": item["attempt_fence_path"],
            })
            log_handle = log_path.open("w", encoding="utf-8")
            # Persist the spec/fence before Popen.  If the coordinator dies in
            # the tiny launch window before it can persist the worker PID,
            # recovery can still locate the worker by its unique spec path.
            item["worker_spec_path"] = str(spec_path)
            _persist(output_dir, state)
            try:
                worker_env = os.environ.copy()
                # Secrets remain process environment only: never in a spec,
                # command line, state file, or log path.
                if args.api_key:
                    worker_env["LLM_API_KEY"] = args.api_key
                if args.base_url:
                    worker_env["LLM_BASE_URL"] = _runner_base_url(args.agent_runner, args.base_url)
                if args.model:
                    worker_env["LLM_MODEL"] = args.model
                worker_env["PYTHONUNBUFFERED"] = "1"
                process = subprocess.Popen(
                    [sys.executable, "-u", str(Path(__file__).resolve()), "--worker-spec", str(spec_path)],
                    stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT,
                    start_new_session=True, cwd=str(ROOT), env=worker_env,
                )
            except Exception as exc:
                log_handle.close()
                launch_result = _result_for_infra(item, "worker_launch", repr(exc))
                _save_case_result(item, launch_result)
                _update_current_attempt_record(
                    item,
                    finished_at=utcnow(),
                    failure_stage="worker_launch",
                    success=False,
                )
                _revoke_attempt_fence(item)
                item.pop("attempt_token", None)
                item["status"] = "runtime_prepared" if item["attempts"] < 2 else "completed"
                _persist(output_dir, state)
                continue
            log_handle.close()
            item["worker_pid"] = process.pid
            item["worker_pgid"] = process.pid
            item["worker_start_ticks"] = _proc_start_ticks(process.pid)
            item.pop("attempt_token", None)
            active[case_id] = (process, time.monotonic(), log_path)
            if args.live_output:
                log_positions[case_id] = 0
                log_pending.pop(case_id, None)
            _persist(output_dir, state)

        if fatal_stop and not active:
            # Fatal quota exhaustion: keep every non-terminal case explicitly
            # resumable. Do not mark skipped work as completed in the summary.
            for cid in state["selected_case_ids"]:
                it = state["cases"][cid]
                if it["status"] not in {"completed", "interrupted", "quota_skipped"}:
                    _save_case_result(it, _result_for_infra(
                        it, FATAL_API_STAGE, "skipped: API quota exhausted, batch stopped"))
                    it["status"] = "quota_skipped"
            _persist(output_dir, state)
            print("[Fatal] batch stopped due to API quota exhaustion", flush=True)
            return False
        if not active:
            if interrupted:
                return False
            # Re-queue a paused (rate-limited) case once its cooldown elapsed,
            # so it is picked up in the next loop iteration's `ready` list.
            if not any(state["cases"][case_id]["status"] in {"runtime_prepared", "leased", "running"}
                       for case_id in state["selected_case_ids"]):
                paused = [state["cases"][cid] for cid in state["selected_case_ids"]
                          if state["cases"][cid]["status"] == "paused"]
                if paused:
                    paused.sort(key=lambda it: it.get("paused_at", 0.0))
                    candidate = paused[0]
                    if time.monotonic() - candidate.get("paused_at", 0.0) >= RATE_LIMIT_COOLDOWN_S:
                        candidate["status"] = "runtime_prepared"
                        print(f"[Warn] {candidate['case']['id']}: re-queuing after "
                              f"rate-limit cooldown", flush=True)
                        _persist(output_dir, state)
                        continue
                    # Still cooling down: wait for it rather than declaring done.
                    time.sleep(0.5)
                    continue
                return not interrupted
            time.sleep(0.1)
            continue
        try:
            time.sleep(0.2)
        except KeyboardInterrupt:
            interrupted = True
        if interrupted:
            # Revoke all result fences before signalling any worker.  This
            # closes the parent-state/late-write window even if a worker is
            # stuck in a child subprocess for a short period.
            for _case_id, (_process, _started, _log_path) in active.items():
                _revoke_attempt_fence(state["cases"][_case_id])
        if args.live_output:
            _stream_log_updates(active, log_positions, log_pending)
        for case_id, (process, started, _log_path) in list(active.items()):
            item = state["cases"][case_id]
            timed_out = time.monotonic() - started > case_timeout
            fatal_worker_stop = fatal_stop and item.get("status") == "running"
            if interrupted or timed_out or fatal_worker_stop:
                signal_to_send = signal.SIGINT if interrupted else signal.SIGTERM
                _revoke_attempt_fence(item)
                _terminate_process_group(
                    process.pid, int(item.get("worker_pgid") or process.pid),
                    first_signal=signal_to_send,
                )
            if process.poll() is None and not (interrupted or timed_out or fatal_worker_stop):
                continue
            if process.poll() is None:
                _terminate_process_group(
                    process.pid, int(item.get("worker_pgid") or process.pid),
                    first_signal=signal.SIGTERM,
                )
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_process_group(
                    process.pid, int(item.get("worker_pgid") or process.pid),
                    first_signal=signal.SIGKILL, grace_seconds=0,
                )
            if _process_group_exists(int(item.get("worker_pgid") or process.pid)):
                _terminate_process_group(
                    process.pid, int(item.get("worker_pgid") or process.pid),
                    first_signal=signal.SIGTERM, grace_seconds=5,
                )
            if args.live_output:
                _stream_log_updates(active, log_positions, log_pending)
            if interrupted or timed_out:
                stage = "interrupted" if interrupted else "worker_timeout"
                result = _result_for_infra(item, stage, "worker stopped before result commit")
            elif fatal_worker_stop:
                result = _result_for_infra(
                    item, FATAL_API_STAGE, "skipped: API quota exhausted, batch stopped"
                )
            else:
                result = _load_attempt_result(item)
                if result is None:
                    stage = FATAL_API_STAGE if fatal_stop else "worker_failed"
                    error = (
                        "skipped: API quota exhausted, batch stopped"
                        if fatal_stop else "worker exited without a fenced result"
                    )
                    result = _result_for_infra(item, stage, error)
            item["status"] = "cleaning"
            _persist(output_dir, state)
            cleanup = _janitor(item, management)
            if not cleanup["ok"]:
                result["cleanup_error"] = cleanup
                result["cleanup_failed"] = True
            _save_case_result(item, result)
            _revoke_attempt_fence(item)
            if cleanup.get("ok"):
                item["control_network_lease"] = None
            failure_stage = result.get("failure_stage", "")
            retry = _should_retry(result, item["attempts"], interrupted)
            # --- API error triage (2026-07-25) -------------------------------
            # Fatal quota exhaustion: stop the whole batch and kill running
            # workers so no more quota is burned. Remaining cases are marked
            # skipped (not failed) and do not auto-retry.
            api_action = _api_error_action(
                failure_stage, item.get("rate_limit_pauses", 0) + 1
            )
            if api_action == "stop":
                fatal_stop = True
                print(f"[Fatal] {case_id}: API quota exhausted — stopping batch "
                      f"and terminating {max(0, len(active) - 1)} running worker(s)", flush=True)
                for rid, (rproc, _rstart, _rlog) in list(active.items()):
                    if rid == case_id:
                        continue
                    other = state["cases"][rid]
                    _revoke_attempt_fence(other)
                    _terminate_process_group(
                        rproc.pid, int(other.get("worker_pgid") or rproc.pid),
                        first_signal=signal.SIGTERM,
                    )
                # Preserve this case as resumable after quota is restored.
                item["status"] = "quota_skipped"
            # Persistent rate limit: pause this case (do NOT count as a
            # failure attempt) and re-queue it after the cooldown so other
            # cases can progress in the meantime.
            elif api_action in {"pause", "finalize"}:
                pauses = item.get("rate_limit_pauses", 0) + 1
                item["rate_limit_pauses"] = pauses
                if api_action == "finalize":
                    print(f"[Warn] {case_id}: rate-limit paused {pauses} times "
                          f"(> {MAX_RATE_LIMIT_PAUSES}), finalizing as rate-limit failure", flush=True)
                    item["status"] = "completed"
                else:
                    print(f"[Warn] {case_id}: rate-limit persistent — pausing, "
                          f"will re-queue after {RATE_LIMIT_COOLDOWN_S}s "
                          f"(pause #{pauses}/{MAX_RATE_LIMIT_PAUSES})", flush=True)
                    item["status"] = "paused"
                    item["paused_at"] = time.monotonic()
                    # Roll back the attempts increment so a rate-limit pause
                    # does not eat into the infra-retry budget.
                    item["attempts"] = max(0, item["attempts"] - 1)
            elif not cleanup.get("ok"):
                # Do not mark a case complete while its scoped control bridge
                # or ContainerLab resources are still present.  Resume will
                # retry cleanup before considering another Agent attempt.
                item["status"] = "cleaning"
            elif interrupted:
                item["status"] = "interrupted"
            else:
                item["status"] = "runtime_prepared" if retry else "completed"
            # ----------------------------------------------------------------
            _update_current_attempt_record(
                item,
                finished_at=utcnow(),
                failure_stage=failure_stage,
                success=bool(result.get("success", False)),
                cleanup_failed=bool(result.get("cleanup_failed", False)),
                cleanup=cleanup,
            )
            item.pop("worker_pid", None)
            item.pop("worker_pgid", None)
            item.pop("worker_start_ticks", None)
            item.pop("worker_spec_path", None)
            item["last_failure_stage"] = failure_stage
            active.pop(case_id)
            if args.live_output:
                pending_line = log_pending.pop(case_id, "")
                if pending_line:
                    print(f"[{case_id}] {pending_line}", flush=True)
                log_positions.pop(case_id, None)
            _persist(output_dir, state)


def _run_cleanup_only(output_dir: Path) -> int:
    """Recover one existing batch without touching its Agent/experiment flow."""
    state_path = output_dir / "batch_state.json"
    if not state_path.exists():
        raise SystemExit(f"cleanup-only requires an existing batch_state.json: {state_path}")
    batch_dir = output_dir / ".batch"
    lock_path = batch_dir / "coordinator.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = lock_path.open("a+")
    try:
        if fcntl is not None:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise SystemExit(f"another coordinator owns {output_dir}") from exc
        state = json.loads(state_path.read_text())
        management = select_management_network()
        _cleanup_incomplete_cases(
            state, output_dir, management, reason="cleanup_only",
            include_prepared=True,
        )
        run_cleanup = _cleanup_run_control_networks(str(state.get("run_id", "")))
        state["last_cleanup_sweep"] = {
            "finished_at": utcnow(),
            "mode": "cleanup_only",
            "run_control_networks": run_cleanup,
        }
        _persist(output_dir, state)
        print(json.dumps(run_cleanup, ensure_ascii=False, indent=2))
        return 0 if run_cleanup.get("ok", False) else 2
    finally:
        if fcntl is not None:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


def main() -> int:
    args = parse_args()
    args.agent_context = normalize_agent_context(args.agent_context)
    agent_exposure_profile = AgentExposureProfile.from_context(
        args.agent_context
    ).model_dump(mode="json")
    os.chdir(ROOT)
    if hasattr(args, "worker_spec"):
        return run_worker(Path(args.worker_spec))
    if args.cleanup_only:
        return _run_cleanup_only(ROOT / args.output)
    if args.noise_activity is not None and args.noise_level != "high":
        raise SystemExit("--noise-activity requires --noise-level high")
    if load_dotenv is not None:
        load_dotenv(ROOT / ".env")
        args.api_key = args.api_key or os.getenv("LLM_API_KEY", "")
        args.base_url = args.base_url or os.getenv("LLM_BASE_URL", "")
        args.model = args.model or os.getenv("LLM_MODEL", "")
    args.base_url = _runner_base_url(args.agent_runner, args.base_url)
    try:
        validate_parallelism(args.parallel)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.resume_parallel < 0:
        raise SystemExit("--resume-parallel must be zero or greater")
    if args.resume_parallel and not args.resume:
        raise SystemExit("--resume-parallel requires --resume")
    if not args.generate_only and not args.environment_only and not args.api_key:
        raise SystemExit("LLM API key is required. Set LLM_API_KEY or pass --api-key. Use --generate-only for a no-Agent preflight.")
    if not args.environment_only and not args.generate_only and args.parallel > len(CONTROL_SUBNETS):
        raise SystemExit(f"--parallel exceeds the {len(CONTROL_SUBNETS)} available Agent control-network leases")
    available_cases = (
        load_manifest_cases(args.case_manifest, expected_template=args.template)
        if args.case_manifest else CASES
    )
    if args.case_manifest and args.max_cases <= 0:
        raise SystemExit("--case-manifest requires an explicit positive --max-cases")
    if args.offset < 0:
        raise SystemExit("--offset must be zero or positive")
    selected = select_cases(args.cases, available_cases)
    selected = selected[args.offset:]
    if args.max_cases > 0:
        selected = selected[:args.max_cases]
    validate_cases(selected)
    output_dir = ROOT / args.output
    batch_dir = output_dir / ".batch"
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("specs", "results", "logs", "work"):
        (batch_dir / name).mkdir(parents=True, exist_ok=True)
    lock_path = batch_dir / "coordinator.lock"
    lock_handle = lock_path.open("a+")
    if fcntl is not None:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit(f"another coordinator owns {output_dir}") from exc
    state_path = output_dir / "batch_state.json"
    resume_state_hint: dict[str, Any] | None = None
    if args.resume and state_path.exists():
        try:
            resume_state_hint = json.loads(state_path.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    if args.resume and not args.reuse_scenarios_from and state_path.exists():
        try:
            prior_options = (resume_state_hint or {}).get("options") or {}
            args.reuse_scenarios_from = str(prior_options.get("reuse_scenarios_from") or "")
        except AttributeError:
            pass
    if args.resume_parallel:
        prior_parallel = (resume_state_hint or {}).get("options", {}).get("parallel")
        if not isinstance(prior_parallel, int) or prior_parallel < 1:
            raise SystemExit("--resume-parallel requires a resumable batch with a valid initial parallel value")
        # The immutable fingerprint remains tied to the original run inputs;
        # only the unfinished worker launch concurrency changes after it matches.
        args.parallel = prior_parallel
    reuse_source: dict[str, Any] | None = None
    if args.reuse_scenarios_from:
        source_root = _reuse_source_path(args.reuse_scenarios_from)
        args.reuse_scenarios_from = str(source_root)
        reuse_source = _load_reuse_source(
            source_root,
            selected,
            agent_context=args.agent_context,
            noise_level=str(getattr(args, "noise_level", "none")),
        )
        reuse_source["_source_root"] = str(source_root)
    fingerprint = _digest_inputs(selected, args)
    state: dict[str, Any] | None = None
    management: dict[str, Any] = {"name": MGMT_NETWORK_NAME}
    resume_cleanup_ids: set[str] = set()
    if args.resume:
        if not state_path.exists():
            raise SystemExit("--resume requires an existing batch_state.json")
        state = json.loads(state_path.read_text())
        known_fingerprints = {
            str(state.get("fingerprint", "")),
            str(state.get("resume_fingerprint", "")),
        }
        if fingerprint not in known_fingerprints:
            if not args.resume_parallel or not _resume_contract_matches(state, selected, args):
                raise SystemExit("batch fingerprint differs; use a new output directory")
            # The runner source is part of the normal fingerprint.  Permit a
            # narrowly-scoped migration only for a scheduler-only resume when
            # every experiment input and fixture still matches the old state.
            migrations = state.setdefault("resume_migrations", [])
            if not any(
                isinstance(entry, dict) and entry.get("to_fingerprint") == fingerprint
                for entry in migrations
            ):
                migrations.append({
                    "at": utcnow(),
                    "reason": "runner_fingerprint_revision",
                    "from_fingerprint": state.get("fingerprint", ""),
                    "to_fingerprint": fingerprint,
                })
            state["resume_fingerprint"] = fingerprint
        if args.resume_parallel:
            state.setdefault("parallel_history", [{
                "parallel": state["options"].get("parallel"),
                "kind": "initial",
                "at": state.get("created_at", ""),
            }])
            history = state["parallel_history"]
            if not history or history[-1].get("parallel") != args.resume_parallel:
                history.append({
                    "parallel": args.resume_parallel,
                    "kind": "resume",
                    "at": utcnow(),
                })
            args.parallel = args.resume_parallel
            try:
                validate_parallelism(args.parallel)
            except ValueError as exc:
                raise SystemExit(str(exc)) from exc
            if not args.environment_only and not args.generate_only and args.parallel > len(CONTROL_SUBNETS):
                raise SystemExit(f"--resume-parallel exceeds the {len(CONTROL_SUBNETS)} available Agent control-network leases")
        # Completed research outcomes are immutable.  Only interrupted or
        # unfinished infrastructure work is eligible to resume.
        resume_cleanup_ids = {
            case_id for case_id, item in state.get("cases", {}).items()
            if item.get("status") in {"running", "leased", "cleaning"}
        }
        for item in state.get("cases", {}).values():
            if item.get("status") in {"interrupted", "quota_skipped"}:
                item["status"] = (
                    "runtime_prepared"
                    if Path(item.get("scenario_dir", "")).is_dir()
                    else "pending"
                )
        for case_id, item in state.get("cases", {}).items():
            if case_id in resume_cleanup_ids:
                item["status"] = "cleaning"
    else:
        if state_path.exists():
            raise SystemExit("output already contains a batch state; use --resume or a new output directory")
        run_id = secrets.token_hex(12)
        state = {
            "schema_version": 1, "created_at": utcnow(), "run_id": run_id, "fingerprint": fingerprint,
            "agent_context": args.agent_context,
            "agent_exposure_profile": agent_exposure_profile,
            "parallel_history": [{"parallel": args.parallel, "kind": "initial", "at": utcnow()}],
            "options": {"template": args.template,
                        "environment_only": args.environment_only, "generate_only": args.generate_only,
                        "parallel": args.parallel, "agent_timeout": args.agent_timeout, "max_turns": args.max_turns,
                        "seed": args.seed, "case_timeout": args.case_timeout,
                        "agent_context": args.agent_context,
                        "agent_exposure_profile": agent_exposure_profile,
                        "noise_level": str(getattr(args, "noise_level", "none")),
                        "noise_activity": getattr(args, "noise_activity", None),
                        "noise_activity_config": noise_activity_config(args),
                        "reuse_scenarios_from": str(getattr(args, "reuse_scenarios_from", "")),
                        "reuse_source_run_id": str((reuse_source or {}).get("run_id", "")),
                        "model": args.model, "agent_runner": args.agent_runner},
            "selected_case_ids": [str(case["id"]) for case in selected], "cases": {},
        }
        for case in selected:
            case_id = str(case["id"])
            lab_name = physical_lab_name(run_id, case_id)
            state["cases"][case_id] = {
                "case": case, "lab_name": lab_name, "status": "pending", "attempts": 0,
                "agent_context": args.agent_context,
                "agent_exposure_profile": agent_exposure_profile,
                "scenario_dir": str(output_dir / "scenarios" / lab_name),
                "result_path": str(batch_dir / "results" / f"{case_id}.json"),
            }
        if reuse_source is not None:
            _prepare_reused_scenarios(state, reuse_source, output_dir)
    if state is None:
        raise RuntimeError("batch state was not initialized")
    _persist(output_dir, state)
    previous_signal_handlers = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }

    def _handle_shutdown(signum, _frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)
    try:
        _generate_cases(state, args, output_dir)
        if args.generate_only:
            return 0 if _complete_generate_only_preflight(
                state, args, output_dir, agent_exposure_profile,
            ) else 2
        _prewarm_cases(state, args, output_dir)
        management = select_management_network()
        if resume_cleanup_ids:
            _cleanup_incomplete_cases(
                state, output_dir, management,
                case_ids=resume_cleanup_ids, reason="resume",
            )
        node_count = max((len((__import__("yaml").safe_load((Path(item["scenario_dir"]) / "clab.yaml").read_text()) or {}).get("topology", {}).get("nodes", {}))
                          for item in state["cases"].values() if item["status"] == "runtime_prepared"), default=0)
        if node_count * args.parallel + int(management.get("endpoints", "0")) > MGMT_CAPACITY:
            raise SystemExit("selected parallelism exceeds the shared management-network endpoint capacity")
        completed_cleanly = _launch_workers(state, args, output_dir, management)
        _persist(output_dir, state)
        results = []
        for case_id in state["selected_case_ids"]:
            result_path = Path(state["cases"][case_id]["result_path"])
            if result_path.exists():
                results.append(json.loads(result_path.read_text()))
        if not completed_cleanly or any(item["status"] != "completed" for item in state["cases"].values()):
            return 2
        if args.strict_success_exit and any(not item.get("success", False) for item in results):
            return 1
        return 0
    finally:
        try:
            _cleanup_incomplete_cases(
                state, output_dir, management, reason="coordinator_exit",
            )
            run_cleanup = _cleanup_run_control_networks(str(state.get("run_id", "")))
            if not run_cleanup.get("ok"):
                print(
                    f"[Cleanup] run-labeled network sweep incomplete: {run_cleanup}",
                    file=sys.stderr, flush=True,
                )
        except Exception as exc:
            # Preserve the original exit/error while leaving an explicit
            # diagnostic in the terminal; a later --resume can retry cleanup.
            print(f"[Cleanup] coordinator sweep failed: {exc}", file=sys.stderr, flush=True)
        for signum, handler in previous_signal_handlers.items():
            signal.signal(signum, handler)
        if fcntl is not None:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
