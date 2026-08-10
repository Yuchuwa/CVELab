#!/usr/bin/env python3
"""Verify enterprise_3tier reference paths for the three app-service candidates.

This runs only the deterministic reference path:

    generate -> ContainerLab deploy -> Ansible setup -> SysField -> destroy

Agent evaluation is intentionally not performed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from clab_builder.orchestrator.composer.scenario import ScenarioPipeline
from clab_builder.orchestrator.composer.verifier import ScenarioVerifier


DMZ_CVE = "CVE-2012-1823"
DATA_CVE = "CVE-2019-9193"
APP_CVES = (
    "CVE-2018-19475",
    "CVE-2021-25646",
    "CVE-2025-68613",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run enterprise_3tier deterministic reference-path verification."
    )
    parser.add_argument(
        "--output-dir",
        default="data/scenarios_app_e2e",
        help="Directory for generated scenarios and verification results.",
    )
    parser.add_argument(
        "--templates-dir",
        default="templates",
        help="Templates directory.",
    )
    parser.add_argument(
        "--atoms-dir",
        default="data/atoms",
        help="Atoms directory.",
    )
    return parser.parse_args()


def summarize(result: dict, app_cve: str, scenario_dir: Path) -> dict:
    return {
        "app_cve": app_cve,
        "scenario_dir": str(scenario_dir),
        "environment_verified": result.get("environment_verified", False),
        "environment_success": result.get("environment_success", False),
        "reference_path_verified": result.get("reference_path_verified", False),
        "success": result.get("success", False),
        "setup_results": result.get("setup_results", {}),
        "reference_path_verification": result.get(
            "reference_path_verification", {}
        ),
        "error": result.get("error", ""),
    }


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline = ScenarioPipeline(
        templates_dir=args.templates_dir,
        atoms_dir=args.atoms_dir,
    )
    verifier = ScenarioVerifier(
        max_turns=1,
        require_agent_success=False,
        atoms_dir=args.atoms_dir,
    )

    results: list[dict] = []

    for app_cve in APP_CVES:
        scenario_name = f"enterprise3-app-{app_cve.lower()}"
        scenario_dir = output_dir / scenario_name
        print(f"\n===== {app_cve} =====", flush=True)

        try:
            pipeline.generate(
                template_name="enterprise_3tier",
                cve_ids=[DMZ_CVE, app_cve, DATA_CVE],
                scenario_name=scenario_name,
                output_dir=str(output_dir),
                seed=1,
            )
            result = verifier.run_environment(str(scenario_dir))
            summary = summarize(result, app_cve, scenario_dir)
        except Exception as exc:  # Keep checking the remaining candidates.
            summary = {
                "app_cve": app_cve,
                "scenario_dir": str(scenario_dir),
                "environment_verified": False,
                "environment_success": False,
                "reference_path_verified": False,
                "success": False,
                "error": repr(exc),
            }

        results.append(summary)
        print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    print("\n===== SUMMARY =====", flush=True)
    print(json.dumps(results, indent=2, ensure_ascii=False), flush=True)
    print(f"Results saved to: {summary_path}", flush=True)

    return 0 if all(item.get("reference_path_verified") for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
