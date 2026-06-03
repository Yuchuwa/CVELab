"""Clab Builder CLI - Unified entry point for atomizer and orchestrator."""

import click
import os
import yaml
from pathlib import Path

from clab_builder import __version__


@click.group()
@click.version_option(version=__version__, prog_name="clab-builder")
def main():
    """Clab Builder - CVE training data generation system."""
    pass


# ── Atom commands (Project 1) ──────────────────────────────────────────

@main.group()
def atom():
    """Single CVE atomization (Agent-driven)."""
    pass


@atom.command("run")
@click.argument("cve_path", nargs=-1, required=True)
@click.option("--output", "-o", default="data/atoms", help="Output directory")
@click.option("--api-key", envvar="LLM_API_KEY", help="LLM API key")
@click.option("--base-url", envvar="LLM_BASE_URL", help="LLM API base URL")
@click.option("--model", envvar="LLM_MODEL", default="claude-sonnet-4-6", help="LLM model")
@click.option("--skip-agent", is_flag=True, help="Only generate ansible config, skip Agent")
@click.option("--force", is_flag=True, help="Force regenerate (overwrite existing atom)")
@click.option("--max-turns", type=int, default=50, help="Maximum agent turns (default: 50)")
def atom_run(cve_path, output, api_key, base_url, model, skip_agent, force, max_turns):
    """Run atomizer on a vulhub CVE directory.

    CVE_PATH can be a vulhub directory (e.g. data/vulhub/log4j/CVE-2021-44228)
    or a short form (e.g. log4j/CVE-2021-44228) resolved against data/vulhub/.
    """
    from clab_builder.atomizer.pipeline import AtomizerPipeline

    for path in cve_path:
        # 解析路径
        vulhub_dir = _resolve_vulhub_path(path)
        if not vulhub_dir:
            click.echo(f"Error: Not found: {path}")
            raise SystemExit(1)

        # 检查是否已存在
        parser_preview = _quick_parse_cve_id(vulhub_dir)
        atom_dir = os.path.join(output, parser_preview)
        if os.path.exists(atom_dir) and not force:
            atom_yaml = os.path.join(atom_dir, "atom.yaml")
            if os.path.exists(atom_yaml):
                click.echo(f"Atom for {parser_preview} already exists. Use --force to overwrite.")
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


def _resolve_vulhub_path(path: str) -> str | None:
    """解析 vulhub CVE 路径"""
    if os.path.isdir(path):
        return path
    # 短格式: log4j/CVE-2021-44228
    candidate = os.path.join("data", "vulhub", path)
    if os.path.isdir(candidate):
        return candidate
    return None


def _quick_parse_cve_id(vulhub_dir: str) -> str:
    """从路径快速提取 CVE ID"""
    parts = Path(vulhub_dir).resolve().parts
    if "vulhub" in list(parts):
        idx = list(parts).index("vulhub")
        return parts[idx + 2]
    return Path(vulhub_dir).name


@atom.command("list")
@click.option("--output", "-o", default="data/atoms", help="Atoms directory")
def atom_list(output):
    """List all generated atoms."""
    atoms_dir = Path(output)
    if not atoms_dir.exists():
        click.echo("No atoms directory found.")
        return

    atoms = sorted([d.name for d in atoms_dir.iterdir() if d.is_dir()])
    if not atoms:
        click.echo("No atoms generated yet.")
        return

    click.echo(f"Generated atoms ({len(atoms)}):")
    for cve_id in atoms:
        atom_yaml = atoms_dir / cve_id / "atom.yaml"
        status = "complete" if atom_yaml.exists() else "incomplete"
        click.echo(f"  {cve_id}  [{status}]")


@atom.command("show")
@click.argument("cve_id")
@click.option("--output", "-o", default="data/atoms", help="Atoms directory")
def atom_show(cve_id, output):
    """Show details of a generated atom."""
    atom_dir = Path(output) / cve_id
    if not atom_dir.exists():
        click.echo(f"Atom not found: {cve_id}")
        raise SystemExit(1)

    # Show atom metadata
    atom_yaml = atom_dir / "atom.yaml"
    if atom_yaml.exists():
        with open(atom_yaml) as f:
            data = yaml.safe_load(f)
        click.echo(yaml.dump(data, default_flow_style=False))
    else:
        click.echo(f"Atom metadata missing for {cve_id}")

    # List files
    click.echo("Files:")
    for f in sorted(atom_dir.rglob("*")):
        if f.is_file():
            click.echo(f"  {f.relative_to(atom_dir)}")


@atom.command("validate")
@click.argument("cve_id")
@click.option("--output", "-o", default="data/atoms", help="Atoms directory")
def atom_validate(cve_id, output):
    """Re-validate an existing atom's playbook."""
    atom_dir = Path(output) / cve_id
    if not atom_dir.exists():
        click.echo(f"Atom not found: {cve_id}")
        raise SystemExit(1)

    click.echo(f"Validating atom: {cve_id}")
    click.echo("TODO: implement re-validation")


# ── Scenario commands (Project 2) ──────────────────────────────────────

@main.group()
def scenario():
    """Multi-CVE scenario orchestration."""
    pass


@scenario.command("generate")
@click.argument("template", type=click.Path(exists=True))
@click.option("--atoms", "-a", help="Comma-separated CVE IDs to include")
@click.option("--output", "-o", default="output", help="Output directory")
def scenario_generate(template, atoms, output):
    """Generate multi-CVE scenario from template + atoms."""
    from clab_builder.orchestrator.generator.topology import TopologyGenerator

    click.echo(f"Generating scenario from template: {template}")

    # Parse atom list
    atom_ids = [a.strip() for a in atoms.split(",")] if atoms else []
    if atom_ids:
        click.echo(f"  Atoms: {atom_ids}")
        # Verify atoms exist
        for cve_id in atom_ids:
            atom_dir = Path("data/atoms") / cve_id
            if not atom_dir.exists():
                click.echo(f"Error: Atom not found for {cve_id}. Run 'atom run {cve_id}' first.")
                raise SystemExit(1)

    generator = TopologyGenerator(template)
    clab_config, ansible_config = generator.generate()

    # Write output
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    clab_file = out_dir / "clab.yaml"
    clab_file.write_text(clab_config)
    click.echo(f"  ContainerLab config: {clab_file}")

    ansible_file = out_dir / "ansible.yaml"
    ansible_file.write_text(yaml.dump(ansible_config, default_flow_style=False))
    click.echo(f"  Ansible config: {ansible_file}")

    click.echo("Scenario generation complete.")


@scenario.command("deploy")
@click.argument("scenario_yaml", type=click.Path(exists=True))
def scenario_deploy(scenario_yaml):
    """Deploy a generated scenario environment."""
    import subprocess

    click.echo(f"Deploying: {scenario_yaml}")
    result = subprocess.run(
        ["clab", "deploy", "-t", scenario_yaml],
        capture_output=True, text=True,
    )
    click.echo(result.stdout)
    if result.returncode != 0:
        click.echo(f"Deploy failed: {result.stderr}")
        raise SystemExit(1)
    click.echo("Deployment complete.")


@scenario.command("validate")
@click.argument("lab_name")
def scenario_validate(lab_name):
    """Validate a deployed environment (network tests + scoring)."""
    from clab_builder.orchestrator.validator.environment import EnvironmentValidator

    click.echo(f"Validating: {lab_name}")
    validator = EnvironmentValidator(lab_name)
    result = validator.validate_all()

    click.echo(f"  Total score: {result.total_score:.1f}/100")
    click.echo(f"  Syntax: {result.syntax_score:.1f}/20")
    click.echo(f"  Deployment: {result.deployment_score:.1f}/30")
    click.echo(f"  Container: {result.container_score:.1f}/20")
    click.echo(f"  Network: {result.network_score:.1f}/15")
    click.echo(f"  CVE: {result.cve_score:.1f}/15")


@scenario.command("attack")
@click.argument("scenario_yaml", type=click.Path(exists=True))
def scenario_attack(scenario_yaml):
    """Execute the composed attack playbook."""
    click.echo(f"Executing attack: {scenario_yaml}")
    click.echo("TODO: implement attack execution from composed playbook")


# ── Catalog commands ───────────────────────────────────────────────────

@main.group()
def catalog():
    """CVE catalog management."""
    pass


@catalog.command("list")
@click.option("--stage", "-s", help="Filter by MITRE ATT&CK stage")
@click.option("--complexity", "-c", help="Filter by complexity (low/medium/high)")
@click.option("--dir", "catalog_dir", default="data/catalogs/verified", help="Catalog directory")
def catalog_list(stage, complexity, catalog_dir):
    """List CVE catalogs."""
    from clab_builder.shared.catalog.loader import CVECatalogLoader

    loader = CVECatalogLoader(catalog_dir=catalog_dir)
    all_catalogs = loader.load_all_catalogs()

    # Apply filters
    results = list(all_catalogs.values())
    if stage:
        results = [c for c in results if c.is_suitable_for_stage(stage)]
    if complexity:
        results = [c for c in results if c.get_complexity_level() == complexity]

    if not results:
        click.echo("No matching CVE catalogs found.")
        return

    click.echo(f"CVE catalogs ({len(results)}):")
    for c in results:
        verified = "verified" if c.is_verified() else "unverified"
        click.echo(f"  {c.basic_info.cve_id:20s}  "
                    f"CVSS {c.basic_info.cvss_score:4.1f}  "
                    f"{c.get_primary_attack_stage():20s}  "
                    f"{c.get_complexity_level():8s}  "
                    f"[{verified}]")


@catalog.command("show")
@click.argument("cve_id")
@click.option("--dir", "catalog_dir", default="data/catalogs/verified", help="Catalog directory")
def catalog_show(cve_id, catalog_dir):
    """Show CVE catalog details."""
    from clab_builder.shared.catalog.loader import CVECatalogLoader

    loader = CVECatalogLoader(catalog_dir=catalog_dir)
    c = loader.load_catalog(cve_id)

    if not c:
        click.echo(f"Catalog not found: {cve_id}")
        raise SystemExit(1)

    click.echo(f"CVE: {c.basic_info.cve_id}")
    click.echo(f"Name: {c.basic_info.name}")
    click.echo(f"CVSS: {c.basic_info.cvss_score}")
    click.echo(f"Description: {c.basic_info.description}")
    click.echo(f"Image: {c.environment.docker_image}")
    click.echo(f"Ports: {c.environment.required_ports}")
    click.echo(f"Primary stage: {c.get_primary_attack_stage()}")
    click.echo(f"Complexity: {c.get_complexity_level()}")
    click.echo(f"Verified: {c.is_verified()}")


@catalog.command("validate")
@click.option("--dir", "catalog_dir", default="data/catalogs/verified", help="Catalog directory")
def catalog_validate(catalog_dir):
    """Validate all catalog quality scores."""
    from clab_builder.shared.catalog.loader import CVECatalogLoader

    loader = CVECatalogLoader(catalog_dir=catalog_dir)
    all_catalogs = loader.load_all_catalogs()

    if not all_catalogs:
        click.echo("No catalogs found.")
        return

    click.echo(f"Validating {len(all_catalogs)} catalogs...")
    for cve_id, c in sorted(all_catalogs.items()):
        status = "OK" if c.is_verified() else "NEEDS REVIEW"
        click.echo(f"  {cve_id}: {status}")
    click.echo("Validation complete.")


if __name__ == "__main__":
    main()
