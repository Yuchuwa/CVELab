"""CVELab CLI - CVE scenario lab builder."""

import click
import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

# 自动加载 .env
load_dotenv()

from clab_builder import __version__


@click.group()
@click.version_option(version=__version__, prog_name="cvelab")
def main():
    """CVELab - CVE scenario lab builder."""
    pass


# ── Generate (only generate files, no deploy) ───────────────────────────

@main.command("generate")
@click.argument("template_name")
@click.option("--cve", "-c", help="Comma-separated CVE IDs (auto-match if omitted)")
@click.option("--name", "-n", help="Scenario name (auto-generated if omitted)")
@click.option("--output", "-o", default="data/scenarios", help="Output directory")
@click.option("--seed", type=int, help="Random seed")
@click.option("--templates-dir", default="templates", help="Templates directory")
@click.option("--atoms-dir", default="data/atoms", help="Atoms directory")
def generate(template_name, cve, name, output, seed, templates_dir, atoms_dir):
    """Generate scenario files from topology template.

    TEMPLATE_NAME is the template directory name (e.g. dmz_simple).
    """
    from clab_builder.orchestrator.composer.scenario import ScenarioPipeline

    cve_ids = [c.strip() for c in cve.split(",")] if cve else None

    click.echo(f"Generating: {template_name}")
    pipeline = ScenarioPipeline(templates_dir=templates_dir, atoms_dir=atoms_dir)
    try:
        scenario = pipeline.generate(
            template_name=template_name,
            cve_ids=cve_ids,
            scenario_name=name,
            output_dir=output,
            seed=seed,
        )
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)

    click.echo(f"  Scenario: {scenario['name']}")
    click.echo(f"  Hash: {scenario['hash']}")
    for inj in scenario["injections"]:
        click.echo(f"  {inj['ip_id']}: {inj['cve_id']} -> {inj['node_name']} ({inj['zone']})")
    click.echo(f"  Output: {output}/{scenario['name']}")
    click.echo("Done.")


# ── Verify (generate + deploy + agent + destroy + save) ─────────────────

@main.command("verify")
@click.argument("template_name")
@click.option("--cve", "-c", help="Comma-separated CVE IDs (auto-match if omitted)")
@click.option("--name", "-n", help="Scenario name (auto-generated if omitted)")
@click.option("--output", "-o", default="data/scenarios", help="Output directory")
@click.option("--seed", type=int, help="Random seed")
@click.option("--templates-dir", default="templates", help="Templates directory")
@click.option("--atoms-dir", default="data/atoms", help="Atoms directory")
@click.option("--api-key", envvar="LLM_API_KEY", help="LLM API key")
@click.option("--base-url", envvar="LLM_BASE_URL", default="", help="LLM API base URL")
@click.option("--model", envvar="LLM_MODEL", default="", help="LLM model")
@click.option("--max-turns", type=int, default=80, help="Max agent turns")
def verify(template_name, cve, name, output, seed, templates_dir, atoms_dir,
           api_key, base_url, model, max_turns):
    """Generate + deploy + agent verify + destroy + save (all-in-one).

    TEMPLATE_NAME is the template directory name (e.g. dmz_simple).
    """
    from clab_builder.orchestrator.composer.scenario import ScenarioPipeline
    from clab_builder.orchestrator.composer.verifier import ScenarioVerifier

    if not api_key:
        click.echo("Error: API key required (set LLM_API_KEY or use --api-key)")
        raise SystemExit(1)

    cve_ids = [c.strip() for c in cve.split(",")] if cve else None

    # 1. Generate
    click.echo("[1/4] Generating scenario...")
    pipeline = ScenarioPipeline(templates_dir=templates_dir, atoms_dir=atoms_dir)
    try:
        scenario = pipeline.generate(
            template_name=template_name,
            cve_ids=cve_ids,
            scenario_name=name,
            output_dir=output,
            seed=seed,
        )
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)

    scenario_dir = os.path.join(output, scenario["name"])
    cves = [inj["cve_id"] for inj in scenario["injections"]]
    click.echo(f"  {scenario['name']}: {', '.join(cves)}")

    # 2. Deploy + configure + agent + destroy + save
    click.echo("[2/4] Running full pipeline...")
    verifier = ScenarioVerifier(max_turns=max_turns)
    result = verifier.run_full(
        scenario_dir=scenario_dir,
        api_key=api_key,
        base_url=base_url,
        model=model,
    )

    # 3. Summary
    click.echo("[3/4] Results:")
    if "flag_verification" in result:
        fv = result["flag_verification"]
        status = "PASS" if fv["all_captured"] else "FAIL"
        click.echo(f"  Status: {status}")
        for node, info in fv["per_target"].items():
            s = "CAPTURED" if info["match"] else "MISSED"
            click.echo(f"    {node}: {s}")
    else:
        click.echo(f"  Status: FAILED ({result.get('error', 'unknown')})")

    click.echo("[4/4] Done.")

    if not result.get("success"):
        raise SystemExit(1)


# ── Batch ────────────────────────────────────────────────────────────────

@main.command("batch")
@click.argument("template_name")
@click.option("--count", "-n", type=int, default=5, help="Number of scenarios")
@click.option("--output", "-o", default="data/scenarios", help="Output directory")
@click.option("--seed", type=int, help="Random seed")
@click.option("--templates-dir", default="templates", help="Templates directory")
@click.option("--atoms-dir", default="data/atoms", help="Atoms directory")
def batch(template_name, count, output, seed, templates_dir, atoms_dir):
    """Batch generate multiple scenarios from a template."""
    from clab_builder.orchestrator.composer.scenario import ScenarioPipeline

    pipeline = ScenarioPipeline(templates_dir=templates_dir, atoms_dir=atoms_dir)
    results = pipeline.batch(
        template_name=template_name,
        count=count,
        output_dir=output,
        seed=seed,
    )

    click.echo(f"Generated {len(results)} scenarios:")
    for s in results:
        cves = [inj["cve_id"] for inj in s["injections"]]
        click.echo(f"  {s['name']}: {', '.join(cves)}")


# ── Atom commands (Project 1) ───────────────────────────────────────────

@main.group()
def atom():
    """Single CVE atomization."""
    pass


@atom.command("run")
@click.argument("cve_path", nargs=-1, required=True)
@click.option("--output", "-o", default="data/atoms", help="Output directory")
@click.option("--api-key", envvar="LLM_API_KEY", help="LLM API key")
@click.option("--base-url", envvar="LLM_BASE_URL", help="LLM API base URL")
@click.option("--model", envvar="LLM_MODEL", default="claude-sonnet-4-6", help="LLM model")
@click.option("--skip-agent", is_flag=True, help="Skip Agent, only generate config")
@click.option("--force", is_flag=True, help="Overwrite existing atom")
@click.option("--max-turns", type=int, default=80, help="Max agent turns")
def atom_run(cve_path, output, api_key, base_url, model, skip_agent, force, max_turns):
    """Run atomizer on a vulhub CVE directory.

    CVE_PATH can be a vulhub directory (e.g. data/vulhub/log4j/CVE-2021-44228)
    or a short form (e.g. log4j/CVE-2021-44228).
    """
    from clab_builder.atomizer.pipeline import AtomizerPipeline

    for path in cve_path:
        vulhub_dir = _resolve_vulhub_path(path)
        if not vulhub_dir:
            click.echo(f"Error: Not found: {path}")
            raise SystemExit(1)

        parser_preview = _quick_parse_cve_id(vulhub_dir)
        atom_dir = os.path.join(output, parser_preview)
        if os.path.exists(atom_dir) and not force:
            atom_yaml = os.path.join(atom_dir, "atom.yaml")
            if os.path.exists(atom_yaml):
                click.echo(f"Atom for {parser_preview} exists. Use --force to overwrite.")
                continue

        click.echo(f"Atomizing: {vulhub_dir}")
        pipeline = AtomizerPipeline(
            vulhub_dir=vulhub_dir,
            output_dir=output,
            max_turns=max_turns,
        )
        result = pipeline.run(
            api_key=api_key or "",
            base_url=base_url or "",
            model=model,
            skip_agent=skip_agent,
        )

        if result.get("success"):
            status = " (agent skipped)" if result.get("agent_skipped") else ""
            click.echo(f"Done: {result['cve_id']}{status} -> {result['output']}")
        else:
            click.echo(f"Failed: {result.get('cve_id')} - {result.get('error', 'unknown')}")
            if not skip_agent:
                raise SystemExit(1)


@atom.command("list")
@click.option("--output", "-o", default="data/atoms", help="Atoms directory")
def atom_list(output):
    """List all generated atoms."""
    atoms_dir = Path(output)
    if not atoms_dir.exists():
        click.echo("No atoms directory.")
        return

    atoms = sorted([d.name for d in atoms_dir.iterdir() if d.is_dir()])
    if not atoms:
        click.echo("No atoms yet.")
        return

    counts = {"verified": 0, "unverified": 0, "incomplete": 0}
    entries = []
    for cve_id in atoms:
        atom_yaml = atoms_dir / cve_id / "atom.yaml"
        if atom_yaml.exists():
            import yaml as _yaml
            data = _yaml.safe_load(atom_yaml.read_text())
            status = "verified" if data.get("verified") else "unverified"
        else:
            status = "incomplete"
        counts[status] += 1
        entries.append((cve_id, status))

    click.echo(f"Atoms ({len(atoms)}): {counts['verified']} verified, {counts['unverified']} unverified, {counts['incomplete']} incomplete")
    for cve_id, status in entries:
        click.echo(f"  {cve_id}  [{status}]")


@atom.command("sysfield")
@click.argument("cve_id", nargs=-1)
@click.option("--output", "-o", default="data/atoms", help="Atoms directory")
def atom_sysfield(cve_id, output):
    """Generate SysField playbooks for existing atoms."""
    from clab_builder.atomizer.output.sysfield_playbook import SysFieldPlaybookGenerator

    atoms_dir = Path(output)
    targets = list(cve_id) if cve_id else [
        d.name for d in sorted(atoms_dir.iterdir())
        if d.is_dir() and (d / "atom.yaml").exists()
    ]
    gen = SysFieldPlaybookGenerator()
    written = []
    for atom_name in targets:
        atom_dir = atoms_dir / atom_name
        if not (atom_dir / "atom.yaml").exists():
            click.echo(f"Skip: {atom_name} (atom.yaml not found)")
            continue
        try:
            written.append(gen.write_atom_playbook(str(atom_dir)))
        except Exception as e:
            click.echo(f"Failed: {atom_name} - {e}")
            continue
    for path in written:
        click.echo(f"Written: {path}")


@atom.command("scale")
@click.option("--vulhub-dir", default="data/vulhub", help="Vulhub data directory")
@click.option("--raw-records", multiple=True, help="raw_records_*.json file; can be repeated")
@click.option("--output", "-o", default="data/atoms", help="Atoms directory")
@click.option("--state-dir", default="data/atom_scale", help="Manifest/dataset output directory")
@click.option("--generated-sources-dir", default="data/generated",
              help="Generated compose sources for raw_records rows")
@click.option("--api-key", envvar="LLM_API_KEY", help="LLM API key")
@click.option("--base-url", envvar="LLM_BASE_URL", default="", help="LLM API base URL")
@click.option("--model", envvar="LLM_MODEL", default="claude-sonnet-4-6", help="LLM model")
@click.option("--skip-agent", is_flag=True, help="Skip Agent, only generate atom config")
@click.option("--force", is_flag=True, help="Re-run existing atoms")
@click.option("--retry-failed", is_flag=True, help="Retry records explicitly marked failed")
@click.option("--limit", type=int, help="Maximum number of queued jobs to run")
@click.option("--cve", "cve_filter", multiple=True,
              help="Restrict to specific CVE ids (e.g. --cve CVE-2014-6271); repeatable")
@click.option("--max-turns", type=int, default=80, help="Max agent turns")
@click.option("--workers", "-w", type=int, default=1,
              help="Parallel worker count for atom generation (1 = sequential)")
@click.option("--discover-only", is_flag=True, help="Only write deduplicated manifest/dataset")
@click.option("--no-parquet", is_flag=True, help="Do not export HuggingFace parquet dataset")
@click.option("--min-disk-gb", type=float, default=5.0,
              help="Pause spawning new builds when free disk (GB) on /var drops below this")
def atom_scale(vulhub_dir, raw_records, output, state_dir, generated_sources_dir,
               api_key, base_url, model, skip_agent, force, retry_failed, limit,
               cve_filter, max_turns, workers, min_disk_gb, discover_only, no_parquet):
    """Scale first-stage atom generation from Vulhub and raw CVE records."""
    from clab_builder.atomizer.scaling import AtomScaleRunner

    runner = AtomScaleRunner(
        vulhub_dir=vulhub_dir,
        raw_records=tuple(raw_records),
        output_dir=output,
        state_dir=state_dir,
        generated_sources_dir=generated_sources_dir,
    )

    records = runner.discover()
    click.echo(f"Discovered {len(records)} unique CVE atom candidates.")
    click.echo(f"Workers: {max(1, workers)} ({'sequential' if workers <= 1 else 'parallel'})")
    click.echo(f"Manifest: {runner.manifest_path}")
    click.echo(f"Dataset JSONL: {runner.dataset_jsonl_path}")

    if discover_only:
        if not no_parquet:
            runner.write_outputs(records, export_parquet=True)
            click.echo(f"Dataset parquet: {runner.dataset_parquet_path}")
        return

    if not skip_agent and not api_key:
        click.echo("Error: API key required unless --skip-agent is used")
        raise SystemExit(1)

    results = runner.run(
        api_key=api_key or "",
        base_url=base_url or "",
        model=model,
        skip_agent=skip_agent,
        force=force,
        limit=limit,
        max_turns=max_turns,
        export_parquet=not no_parquet,
        workers=max(1, workers),
        min_disk_gb=min_disk_gb,
        cve_filter=cve_filter,
        retry_failed=retry_failed,
    )
    counts = {}
    for record in results:
        counts[record.status] = counts.get(record.status, 0) + 1
    click.echo(f"Done: {counts}")
    click.echo(f"Dataset JSONL: {runner.dataset_jsonl_path}")
    if not no_parquet:
        click.echo(f"Dataset parquet: {runner.dataset_parquet_path}")


# ── SysField integration ─────────────────────────────────────────────────

@main.group()
def sysfield():
    """Export/run scenarios with SysField."""
    pass


@sysfield.command("export")
@click.argument("scenario_dir")
@click.option("--output", "-o", help="Output playbook path")
@click.option("--atoms-dir", default="data/atoms", help="Atoms directory")
@click.option("--actor-node", default="attacker", help="SysField actor node name")
def sysfield_export(scenario_dir, output, atoms_dir, actor_node):
    """Export a generated CVELab scenario as a SysField playbook."""
    from clab_builder.orchestrator.composer.sysfield_exporter import SysFieldExporter

    exporter = SysFieldExporter(atoms_dir=atoms_dir)
    try:
        out = exporter.export(
            scenario_dir=scenario_dir,
            output_file=output,
            actor_node=actor_node,
        )
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)

    click.echo(f"SysField playbook: {out}")


# ── Benchmark ────────────────────────────────────────────────────────────

@main.group()
def benchmark():
    """Run attacker-agent benchmarks against generated scenarios."""
    pass


@benchmark.command("run")
@click.option("--scenario", "scenario_dir", required=True, help="Generated scenario directory")
@click.option("--agent-spec", required=True, help="Agent spec YAML")
@click.option("--runs-dir", default="runs", help="Benchmark artifact output directory")
@click.option("--atoms-dir", default="data/atoms", help="Atoms directory for runtime checks")
@click.option("--skip-deploy", is_flag=True, help="Use an already deployed scenario")
@click.option("--keep-running", is_flag=True, help="Do not destroy the lab after the run")
@click.option("--skip-runtime-validation", is_flag=True, help="Skip pre-agent runtime checks")
def benchmark_run(scenario_dir, agent_spec, runs_dir, atoms_dir, skip_deploy,
                  keep_running, skip_runtime_validation):
    """Deploy a scenario, run an agent in attacker, score captured flags."""
    from clab_builder.orchestrator.benchmark import AgentSpec, BenchmarkRunner

    spec = AgentSpec.load(agent_spec)
    runner = BenchmarkRunner(
        scenario_dir=scenario_dir,
        agent_spec=spec,
        runs_dir=runs_dir,
        atoms_dir=atoms_dir,
        skip_deploy=skip_deploy,
        keep_running=keep_running,
        skip_runtime_validation=skip_runtime_validation,
    )
    try:
        result = runner.run()
    except Exception as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)

    score = result.get("score", {})
    click.echo(f"Run: {result['run_dir']}")
    click.echo(f"Agent: {result['agent']}")
    click.echo(f"Scenario: {result['scenario']}")
    if score:
        click.echo(
            f"Score: {score.get('captured', 0)}/{score.get('total', 0)} "
            f"({score.get('score', 0.0):.2f})"
        )
    if not result.get("success"):
        click.echo(f"Status: FAIL {result.get('error', '')}".rstrip())
        raise SystemExit(1)
    click.echo("Status: PASS")


@benchmark.command("validate")
@click.argument("scenario_dir")
@click.option("--atoms-dir", default="data/atoms", help="Atoms directory for service port checks")
def benchmark_validate(scenario_dir, atoms_dir):
    """Validate a deployed scenario before running benchmark agents."""
    from clab_builder.orchestrator.benchmark.runtime_validator import RuntimeValidator

    result = RuntimeValidator(scenario_dir, atoms_dir=atoms_dir).validate()
    click.echo(f"Scenario: {result['scenario']}")
    click.echo(f"Status: {'PASS' if result['success'] else 'FAIL'}")
    for check in result["checks"]:
        status = "OK" if check["success"] else "FAIL"
        required = "required" if check.get("required", True) else "optional"
        click.echo(f"  {status} [{required}] {check['name']}")
    if not result["success"]:
        raise SystemExit(1)


def _resolve_vulhub_path(path: str) -> str | None:
    if os.path.isdir(path):
        return path
    candidate = os.path.join("data", "vulhub", path)
    if os.path.isdir(candidate):
        return candidate
    return None


def _quick_parse_cve_id(vulhub_dir: str) -> str:
    parts = Path(vulhub_dir).resolve().parts
    if "vulhub" in list(parts):
        idx = list(parts).index("vulhub")
        return parts[idx + 2]
    return Path(vulhub_dir).name


if __name__ == "__main__":
    main()
