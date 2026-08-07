#!/usr/bin/env python3
"""Run a controlled batch of Guided-Agent enterprise_3tier experiments.

Each case is isolated by its scenario name.  By default cases run serially;
``--parallel N`` enables a bounded number of concurrent trials when the host
has enough Docker/ContainerLab capacity:

    generate -> deploy/setup -> Guided Agent -> objective verification -> destroy

The cases are deliberately explicit.  This keeps the experiment comparable and
avoids the random combinations produced by the generic ``cvelab batch`` command.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import signal
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
from clab_builder.orchestrator.composer.verifier import ScenarioVerifier
from clab_builder.shared.models.artifact_contracts import (
    load_scenario_manifest,
    load_verification_result,
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
    "agent_transport", "cleanup_failed",
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
        choices=("guided", "no-guide", "no-hint", "l0", "l1", "l2"),
        default="guided",
        help="Agent context: guided, no-guide, no-hint (legacy alias), or "
             "difficulty level l0/l1/l2 (l0=entry IP only, l1=+topology, "
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
        help="Noise level key from the template's noise_levels (none/baseline). "
             "Inserts benign decoy nodes into zone LANs; orthogonal to --agent-context.",
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


def load_manifest_cases(path_value: str) -> tuple[dict[str, object], ...]:
    path = Path(path_value)
    if not path.is_absolute():
        path = ROOT / path
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read case manifest {path}: {exc}") from exc
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


def summarize(case: dict[str, object], scenario_dir: Path, result: dict) -> dict:
    agent_result = result.get("agent_result") or {}
    return {
        "case_id": case["id"],
        "purpose": case["purpose"],
        "cves": case["cves"],
        "asset_variants": case.get("asset_variants", {}),
        "resolved_asset_bindings": result.get("resolved_asset_bindings", {}),
        "scenario_dir": str(scenario_dir),
        "agent_context": result.get("agent_context", "guided"),
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
        "hint_profile": result.get("hint_profile", ""),
        "prompt_hygiene": result.get("prompt_hygiene", {}),
        "agent_structured_result": bool(agent_result.get("structured_result", False)),
        "agent_partial_result": bool(agent_result.get("partial_result", False)),
        "observed_progress": agent_result.get("observed_progress", {}),
        "decoy_interactions": result.get("decoy_interactions", {}),
        "sysarmor": result.get("sysarmor", {}),
        "error": result.get("error", ""),
    }


def _agent_attempt_evaluated(result: dict[str, Any]) -> bool:
    """Whether an Agent trial already consumed research/API resources."""
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
    digest.update(json.dumps({
        "templates_dir": args.templates_dir, "atoms_dir": args.atoms_dir,
        "max_turns": args.max_turns, "agent_timeout": args.agent_timeout,
        "environment_only": args.environment_only, "generate_only": args.generate_only,
        "validation_mode": "guided_agent",
        "agent_context": args.agent_context,
        "noise_level": str(getattr(args, "noise_level", "none")),
        "agent_runner": args.agent_runner,
        "model": args.model,
        "sysarmor": bool(getattr(args, "sysarmor", False)),
        "sysarmor_detection": bool(getattr(args, "sysarmor_detection", False)),
        "sysarmor_signal_window": int(getattr(args, "sysarmor_signal_window", 30)),
    }, sort_keys=True).encode())
    paths = [ROOT / "templates" / "enterprise_3tier" / "template.yaml", Path(__file__),
             ROOT / "src/clab_builder/orchestrator/composer/verifier.py",
             ROOT / "src/clab_builder/orchestrator/composer/scenario_runner.py",
             ROOT / "src/clab_builder/orchestrator/composer/openai_scenario_runner.py"]
    for case in selected:
        for cve in case["cves"]:
            atom_dir = ROOT / args.atoms_dir / str(cve)
            paths.extend([atom_dir / "atom.yaml", atom_dir / "exploit_guide.yaml",
                          atom_dir / "source_bundle" / "manifest.json", atom_dir / "runtime" / "manifest.json"])
    for path in paths:
        digest.update(str(path).encode())
        if path.is_file():
            digest.update(path.read_bytes())
        else:
            digest.update(b"<missing>")
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


def release_control_lease(lease: dict[str, Any] | None) -> None:
    if lease and lease.get("network_name"):
        subprocess.run(["docker", "network", "rm", str(lease["network_name"])],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)


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


def run_worker(spec_path: Path) -> int:
    """Hidden worker entrypoint; spec contains no secret/API key."""
    spec = json.loads(spec_path.read_text())
    result_path = Path(spec["result_path"])
    started = utcnow()
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
                    "ansible_paths": spec["ansible_paths"], "mgmt_network": spec.get("mgmt_network") or {},
                    "control_network_lease": spec.get("control_network_lease") or {},
                    "noise_level": spec.get("noise_level", "none"),
                },
                agent_context=str(spec.get("agent_context", "guided")),
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
                  "success": False, "failure_stage": stage, "error": repr(exc),
                  "execution_complete": False}
    except Exception as exc:
        result = {"case_id": spec["case"]["id"], "purpose": spec["case"]["purpose"],
                  "cves": spec["case"]["cves"], "scenario_dir": str(spec["scenario_dir"]),
                  "success": False, "failure_stage": "worker_failed", "error": repr(exc),
                  "execution_complete": False}
    atomic_json(result_path, result)
    return 0


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
    atomic_json(output_dir / "summary.json", {
        "created_at": utcnow(), "run_id": state["run_id"], "template": "enterprise_3tier",
        "validation_mode": "guided_agent", "environment_only": state["options"]["environment_only"],
        "agent_context": state["options"].get("agent_context", "guided"),
        "noise_level": state["options"].get("noise_level", "none"),
        "model": state["options"].get("model", ""),
        "agent_runner": state["options"].get("agent_runner", "claude"),
        # Top-level validation-round tag: identifies which batch this summary
        # belongs to so downstream level/agent experiments can reuse a set of
        # Ranges with a traceable "validated in round X" provenance. Each
        # per-scenario verify_result.json also carries its own validation_round.
        "validation_round": {
            "run_id": state["run_id"],
            "agent_context": state["options"].get("agent_context", "guided"),
            "noise_level": state["options"].get("noise_level", "none"),
            "model": state["options"].get("model", ""),
            "agent_runner": state["options"].get("agent_runner", "claude"),
            "environment_only": state["options"]["environment_only"],
            "max_turns": state["options"].get("max_turns"),
            "agent_timeout": state["options"].get("agent_timeout"),
            "created_at": state.get("created_at", utcnow()),
        },
        "selected_cases": state["selected_case_ids"], "results": ordered,
        "case_states": {key: value["status"] for key, value in state["cases"].items()},
        "fingerprint": state["fingerprint"],
    })


def _persist(output_dir: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = utcnow()
    atomic_json(output_dir / "batch_state.json", state)
    _write_summary(output_dir, state)


def _result_for_infra(case_state: dict[str, Any], stage: str, error: str) -> dict[str, Any]:
    case = case_state["case"]
    return {
        "case_id": case["id"], "purpose": case["purpose"], "cves": case["cves"],
        "scenario_dir": case_state["scenario_dir"], "success": False,
        "failure_stage": stage, "error": error, "execution_complete": False,
    }


def _save_case_result(case_state: dict[str, Any], result: dict[str, Any]) -> None:
    atomic_json(Path(case_state["result_path"]), result)


def _generate_cases(state: dict[str, Any], args: argparse.Namespace, output_dir: Path) -> None:
    pipeline = ScenarioPipeline(
        templates_dir=args.templates_dir, atoms_dir=args.atoms_dir,
        default_validation_mode="guided_agent",
    )
    sysfield_exporter = SysFieldExporter(atoms_dir=args.atoms_dir)
    scenarios_root = output_dir / "scenarios"
    for case_id in state["selected_case_ids"]:
        item = state["cases"][case_id]
        if item["status"] not in {"pending", "generation_failed"}:
            continue
        try:
            pipeline.generate(
                template_name="enterprise_3tier", cve_ids=list(item["case"]["cves"]),
                scenario_name=item["lab_name"], output_dir=str(scenarios_root), seed=args.seed,
                validation_mode="guided_agent",
                agent_context=str(getattr(args, "agent_context", "guided")),
                noise_level=str(getattr(args, "noise_level", "none")),
            )
            if bool(getattr(args, "sysarmor_detection", False)) and bool(getattr(args, "environment_only", False)):
                sysfield_exporter.export(str(scenarios_root / item["lab_name"]))
            item["status"] = "generated"
            item["scenario_dir"] = str(scenarios_root / item["lab_name"])
        except Exception as exc:
            item["status"] = "completed"
            _save_case_result(item, _result_for_infra(item, "generation", repr(exc)))
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
                check = verifier.prepare_runtime_images(str(scenario_dir))
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


def _janitor(case_state: dict[str, Any], management: dict[str, Any]) -> dict[str, Any]:
    """Precise cleanup only for resources belonging to one known lab/lease."""
    topology = Path(case_state["scenario_dir"]) / "clab.yaml"
    command = ["clab", "destroy", "-t", str(topology), "--cleanup"]
    if management.get("name"):
        command.append("--keep-mgmt-net")
    destroy = subprocess.run(command, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    release_control_lease(case_state.get("control_network_lease"))
    output = f"{destroy.stdout}\n{destroy.stderr}".lower()
    absent = "no containerlab containers found" in output
    return {"ok": destroy.returncode == 0 or absent, "stdout": destroy.stdout[-1000:], "stderr": destroy.stderr[-1000:]}


def _worker_spec(state: dict[str, Any], case_state: dict[str, Any], args: argparse.Namespace,
                 output_dir: Path, worker_id: int, management: dict[str, Any]) -> Path:
    work_dir = output_dir / ".batch" / "work" / case_state["case"]["id"]
    spec = {
        "run_id": state["run_id"], "worker_id": str(worker_id), "case": case_state["case"],
        "lab_name": case_state["lab_name"], "scenario_dir": case_state["scenario_dir"],
        "result_path": case_state["result_path"], "lab_lock_path": str(work_dir / "lab.lock"),
        "atoms_dir": args.atoms_dir, "max_turns": args.max_turns, "agent_timeout": args.agent_timeout,
        "environment_only": args.environment_only,
        "agent_context": str(getattr(args, "agent_context", "guided")).replace("-", "_"),
        "noise_level": str(getattr(args, "noise_level", "none")),
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
        ready = [state["cases"][case_id] for case_id in state["selected_case_ids"]
                 if state["cases"][case_id]["status"] in {"runtime_prepared", "leased"}]
        while ready and len(active) < args.parallel and not interrupted and not fatal_stop:
            item = ready.pop(0)
            case_id = item["case"]["id"]
            if not args.environment_only and not args.generate_only and not item.get("control_network_lease"):
                try:
                    item["control_network_lease"] = control_lease(
                        state["run_id"], case_id, scenario_reserved_subnets(Path(item["scenario_dir"]))
                    )
                    item["status"] = "leased"
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
            spec_path = _worker_spec(state, item, args, output_dir, len(active) + 1, management)
            log_path = output_dir / ".batch" / "logs" / f"{case_id}-a{item['attempts']}.log"
            item.setdefault("attempt_records", []).append({
                "attempt": item["attempts"], "started_at": utcnow(), "log_path": str(log_path),
            })
            log_handle = log_path.open("w", encoding="utf-8")
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
                item["attempt_records"][-1].update({
                    "finished_at": utcnow(), "failure_stage": "worker_launch", "success": False,
                })
                item["status"] = "runtime_prepared" if item["attempts"] < 2 else "completed"
                _persist(output_dir, state)
                continue
            log_handle.close()
            active[case_id] = (process, time.monotonic(), log_path)
            if args.live_output:
                log_positions[case_id] = 0
                log_pending.pop(case_id, None)
            _persist(output_dir, state)

        if fatal_stop and not active:
            # Fatal quota exhaustion: finalize every non-terminal case as
            # skipped so --resume won't re-run them and the summary reflects
            # the stop cause. Do not mark them as failures (success=False
            # already set by the infra-result stub); keep failure_stage.
            for cid in state["selected_case_ids"]:
                it = state["cases"][cid]
                if it["status"] not in {"completed", "interrupted"}:
                    _save_case_result(it, _result_for_infra(
                        it, FATAL_API_STAGE, "skipped: API quota exhausted, batch stopped"))
                    it["status"] = "completed"
            _persist(output_dir, state)
            print("[Fatal] batch stopped due to API quota exhaustion", flush=True)
            return False
        if not active:
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
        if args.live_output:
            _stream_log_updates(active, log_positions, log_pending)
        for case_id, (process, started, _log_path) in list(active.items()):
            item = state["cases"][case_id]
            timed_out = time.monotonic() - started > case_timeout
            if interrupted or timed_out:
                signal_to_send = signal.SIGINT if interrupted else signal.SIGTERM
                try:
                    os.killpg(process.pid, signal_to_send)
                except ProcessLookupError:
                    pass
                if timed_out:
                    _save_case_result(item, _result_for_infra(item, "worker_timeout", "worker wall-clock timeout"))
            if process.poll() is None and not (interrupted or timed_out):
                continue
            if process.poll() is None:
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if args.live_output:
                _stream_log_updates(active, log_positions, log_pending)
            result_path = Path(item["result_path"])
            if not result_path.exists():
                stage = FATAL_API_STAGE if fatal_stop else ("interrupted" if interrupted else "worker_failed")
                error = (
                    "skipped: API quota exhausted, batch stopped"
                    if fatal_stop else "worker exited without a result"
                )
                _save_case_result(item, _result_for_infra(item, stage, error))
            try:
                result = json.loads(result_path.read_text())
            except (OSError, json.JSONDecodeError):
                result = _result_for_infra(item, "worker_failed", "worker produced invalid result JSON")
                _save_case_result(item, result)
            item["status"] = "cleaning"
            _persist(output_dir, state)
            cleanup = _janitor(item, management)
            if not cleanup["ok"]:
                result["cleanup_error"] = cleanup
                result["cleanup_failed"] = True
                _save_case_result(item, result)
            release_control_lease(item.get("control_network_lease"))
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
                    try:
                        os.killpg(rproc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                # This case is terminal.
                item["status"] = "completed"
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
            elif interrupted:
                item["status"] = "interrupted"
            else:
                item["status"] = "runtime_prepared" if retry else "completed"
            # ----------------------------------------------------------------
            item["attempt_records"][-1].update({
                "finished_at": utcnow(), "failure_stage": failure_stage,
                "success": bool(result.get("success", False)),
                "cleanup_failed": bool(result.get("cleanup_failed", False)),
                "cleanup": cleanup,
            })
            item["last_failure_stage"] = failure_stage
            active.pop(case_id)
            if args.live_output:
                pending_line = log_pending.pop(case_id, "")
                if pending_line:
                    print(f"[{case_id}] {pending_line}", flush=True)
                log_positions.pop(case_id, None)
            _persist(output_dir, state)


def main() -> int:
    args = parse_args()
    args.agent_context = args.agent_context.replace("-", "_")
    os.chdir(ROOT)
    if hasattr(args, "worker_spec"):
        return run_worker(Path(args.worker_spec))
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
    if not args.generate_only and not args.environment_only and not args.api_key:
        raise SystemExit("LLM API key is required. Set LLM_API_KEY or pass --api-key. Use --generate-only for a no-Agent preflight.")
    if not args.environment_only and not args.generate_only and args.parallel > len(CONTROL_SUBNETS):
        raise SystemExit(f"--parallel exceeds the {len(CONTROL_SUBNETS)} available Agent control-network leases")
    available_cases = load_manifest_cases(args.case_manifest) if args.case_manifest else CASES
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
    fingerprint = _digest_inputs(selected, args)
    if args.resume:
        if not state_path.exists():
            raise SystemExit("--resume requires an existing batch_state.json")
        state = json.loads(state_path.read_text())
        if state.get("fingerprint") != fingerprint:
            raise SystemExit("batch fingerprint differs; use a new output directory")
        # Completed research outcomes are immutable.  Only interrupted or
        # unfinished infrastructure work is eligible to resume.
        for item in state.get("cases", {}).values():
            if item.get("status") == "interrupted":
                item["status"] = "runtime_prepared"
        for item in state.get("cases", {}).values():
            if item.get("status") in {"interrupted", "running", "leased", "cleaning"}:
                release_control_lease(item.get("control_network_lease"))
                item["control_network_lease"] = None
                item["status"] = "runtime_prepared" if Path(item.get("scenario_dir", "")).is_dir() else "pending"
    else:
        if state_path.exists():
            raise SystemExit("output already contains a batch state; use --resume or a new output directory")
        run_id = secrets.token_hex(12)
        state = {
            "schema_version": 1, "created_at": utcnow(), "run_id": run_id, "fingerprint": fingerprint,
            "options": {"environment_only": args.environment_only, "generate_only": args.generate_only,
                        "parallel": args.parallel, "agent_timeout": args.agent_timeout, "max_turns": args.max_turns,
                        "agent_context": args.agent_context,
                        "noise_level": str(getattr(args, "noise_level", "none")),
                        "model": args.model, "agent_runner": args.agent_runner},
            "selected_case_ids": [str(case["id"]) for case in selected], "cases": {},
        }
        for case in selected:
            case_id = str(case["id"])
            lab_name = physical_lab_name(run_id, case_id)
            state["cases"][case_id] = {
                "case": case, "lab_name": lab_name, "status": "pending", "attempts": 0,
                "scenario_dir": str(output_dir / "scenarios" / lab_name),
                "result_path": str(batch_dir / "results" / f"{case_id}.json"),
            }
    _persist(output_dir, state)
    try:
        _generate_cases(state, args, output_dir)
        if args.generate_only:
            for case_id in state["selected_case_ids"]:
                item = state["cases"][case_id]
                if item["status"] == "generated":
                    item["status"] = "completed"
                    _save_case_result(item, {"case_id": case_id, "purpose": item["case"]["purpose"],
                        "cves": item["case"]["cves"], "scenario_dir": item["scenario_dir"],
                        "generated": True, "preflight": True, "success": True,
                        "agent_context": args.agent_context,
                        "noise_level": str(getattr(args, "noise_level", "none")),
                        "sysarmor": {
                            "enabled": bool(getattr(args, "sysarmor", False)),
                            "detection": bool(getattr(args, "sysarmor_detection", False)),
                            "signal_window": int(getattr(args, "sysarmor_signal_window", 30)),
                        },
                        "execution_complete": True})
            _persist(output_dir, state)
            return 0
        _prewarm_cases(state, args, output_dir)
        management = select_management_network()
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
        if fcntl is not None:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
