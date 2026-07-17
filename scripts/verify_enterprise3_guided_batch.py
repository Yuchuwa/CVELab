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
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from dotenv import load_dotenv
except ImportError:  # The caller may provide all settings through the environment.
    load_dotenv = None

from clab_builder.orchestrator.composer.scenario import ScenarioPipeline
from clab_builder.orchestrator.composer.verifier import ScenarioVerifier


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases",
        default="all",
        help="Comma-separated case IDs, or 'all' (default).",
    )
    parser.add_argument(
        "--output",
        default="data/scenarios_guided_batch",
        help="Root directory for generated scenarios and summary.json.",
    )
    parser.add_argument("--templates-dir", default="templates")
    parser.add_argument("--atoms-dir", default="data/atoms")
    parser.add_argument("--max-turns", type=int, default=80)
    parser.add_argument(
        "--agent-timeout",
        type=int,
        default=1800,
        help="Maximum seconds for one Agent subprocess (default: 1800).",
    )
    parser.add_argument(
        "--strict-guide-compatibility",
        action="store_true",
        help="Deprecated compatibility flag; Guide alignment warnings never block Agent.",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Maximum number of independent Range trials to run concurrently "
            "(default: 1; use 2 only when Docker/ContainerLab resources allow it)."
        ),
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--api-key", default=os.getenv("LLM_API_KEY", ""))
    parser.add_argument("--base-url", default=os.getenv("LLM_BASE_URL", ""))
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", ""))
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
    return parser.parse_args()


def select_cases(value: str) -> list[dict[str, object]]:
    if value.strip().lower() == "all":
        return list(CASES)
    wanted = [item.strip() for item in value.split(",") if item.strip()]
    known = {case["id"]: case for case in CASES}
    unknown = [item for item in wanted if item not in known]
    if unknown:
        raise SystemExit(
            "Unknown case ID(s): " + ", ".join(unknown)
            + "\nAvailable: " + ", ".join(known)
        )
    return [known[item] for item in wanted]


def summarize(case: dict[str, object], scenario_dir: Path, result: dict) -> dict:
    agent_result = result.get("agent_result") or {}
    return {
        "case_id": case["id"],
        "purpose": case["purpose"],
        "cves": case["cves"],
        "scenario_dir": str(scenario_dir),
        "success": bool(result.get("success", False)),
        "environment_verified": bool(result.get("environment_verified", False)),
        "environment_success": bool(result.get("environment_success", False)),
        "range_build_verified": bool(result.get("range_build_verified", False)),
        "attack_graph_valid": bool(result.get("attack_graph_valid", False)),
        "attack_path_reachable": bool(result.get("attack_path_reachable", False)),
        "guided_trial_evaluated": bool(result.get("guided_trial_evaluated", False)),
        "guided_trial_success": bool(result.get("guided_trial_success", False)),
        "objective_achieved": bool(result.get("objective_achieved", False)),
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
        "agent_structured_result": bool(agent_result.get("structured_result", False)),
        "agent_partial_result": bool(agent_result.get("partial_result", False)),
        "observed_progress": agent_result.get("observed_progress", {}),
        "error": result.get("error", ""),
    }


def save_summary(
    path: Path,
    *,
    selected: list[dict[str, object]],
    results: list[dict],
    environment_only: bool,
) -> None:
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "template": "enterprise_3tier",
        "validation_mode": "guided_agent",
        "environment_only": environment_only,
        "selected_cases": [case["id"] for case in selected],
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def run_case(
    case: dict[str, object],
    *,
    output_dir: Path,
    templates_dir: str,
    atoms_dir: str,
    max_turns: int,
    agent_timeout: int,
    strict_guide_compatibility: bool,
    seed: int,
    api_key: str,
    base_url: str,
    model: str,
    generate_only: bool,
    environment_only: bool,
) -> dict:
    """Run one isolated case; safe to call from a batch worker."""
    scenario_name = f"enterprise3-guided-{case['id']}"
    scenario_dir = output_dir / scenario_name
    cves = list(case["cves"])

    try:
        # Keep these objects local to the worker.  They contain no shared
        # mutable execution state, and this also prevents a future verifier
        # option from leaking between concurrent trials.
        pipeline = ScenarioPipeline(
            templates_dir=templates_dir,
            atoms_dir=atoms_dir,
            default_validation_mode="guided_agent",
        )
        verifier = ScenarioVerifier(
            max_turns=max_turns,
            agent_timeout=agent_timeout,
            require_agent_success=not environment_only,
            atoms_dir=atoms_dir,
            validation_mode="guided_agent",
            strict_guide_compatibility=strict_guide_compatibility,
        )
        pipeline.generate(
            template_name="enterprise_3tier",
            cve_ids=cves,
            scenario_name=scenario_name,
            output_dir=str(output_dir),
            seed=seed,
            validation_mode="guided_agent",
        )
        if generate_only:
            return {
                "case_id": case["id"],
                "purpose": case["purpose"],
                "cves": cves,
                "scenario_dir": str(scenario_dir),
                "generated": True,
                "preflight": True,
            }

        result = verifier.run_full(
            scenario_dir=str(scenario_dir),
            api_key=api_key,
            base_url=base_url,
            model=model,
            environment_only=environment_only,
        )
        return summarize(case, scenario_dir, result)
    except Exception as exc:  # Keep remaining controlled cases running.
        return {
            "case_id": case["id"],
            "purpose": case["purpose"],
            "cves": cves,
            "scenario_dir": str(scenario_dir),
            "success": False,
            "failure_stage": "generation_or_runner_exception",
            "error": repr(exc),
        }


def main() -> int:
    args = parse_args()
    # Resolve the project-relative defaults consistently even when the script
    # is invoked through an absolute path from another working directory.
    os.chdir(ROOT)
    if load_dotenv is not None:
        load_dotenv(ROOT / ".env")
        args.api_key = args.api_key or os.getenv("LLM_API_KEY", "")
        args.base_url = args.base_url or os.getenv("LLM_BASE_URL", "")
        args.model = args.model or os.getenv("LLM_MODEL", "")

    selected = select_cases(args.cases)
    if args.parallel < 1:
        raise SystemExit("--parallel must be at least 1")
    if not args.generate_only and not args.environment_only and not args.api_key:
        raise SystemExit(
            "LLM API key is required. Set LLM_API_KEY or pass --api-key. "
            "Use --generate-only for a no-Agent preflight."
        )

    output_dir = ROOT / args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"

    print(
        f"Selected {len(selected)} enterprise_3tier case(s); "
        f"parallel workers={args.parallel}"
    )
    options = {
        "output_dir": output_dir,
        "templates_dir": args.templates_dir,
        "atoms_dir": args.atoms_dir,
        "max_turns": args.max_turns,
        "agent_timeout": args.agent_timeout,
        "strict_guide_compatibility": args.strict_guide_compatibility,
        "seed": args.seed,
        "api_key": args.api_key,
        "base_url": args.base_url,
        "model": args.model,
        "generate_only": args.generate_only,
        "environment_only": args.environment_only,
    }
    results_by_case: dict[str, dict] = {}

    def record(item: dict) -> None:
        results_by_case[str(item["case_id"])] = item
        # Preserve the declared case order even when futures finish out of order.
        ordered = [
            results_by_case[str(case["id"])]
            for case in selected
            if str(case["id"]) in results_by_case
        ]
        save_summary(
            summary_path,
            selected=selected,
            results=ordered,
            environment_only=args.environment_only,
        )
        print(json.dumps(item, indent=2, ensure_ascii=False))

    if args.parallel == 1:
        for index, case in enumerate(selected, start=1):
            print(f"\n[{index}/{len(selected)}] {case['id']}: {' -> '.join(case['cves'])}")
            record(run_case(case, **options))
    else:
        for index, case in enumerate(selected, start=1):
            print(f"Queued [{index}/{len(selected)}] {case['id']}: {' -> '.join(case['cves'])}")
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {
                executor.submit(run_case, case, **options): case
                for case in selected
            }
            for future in as_completed(futures):
                record(future.result())

    results = [
        results_by_case[str(case["id"])]
        for case in selected
        if str(case["id"]) in results_by_case
    ]

    print(f"\nSummary saved to: {summary_path}")
    if args.generate_only:
        return 0 if all(item.get("generated") for item in results) else 1
    return 0 if all(item.get("success") for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
