"""Scenario — 主入口，串联 Template → Match → Assemble pipeline"""

from typing import Optional
from pathlib import Path

from clab_builder.orchestrator.composer.template_loader import TemplateLoader
from clab_builder.orchestrator.composer.atom_loader import AtomLoader
from clab_builder.orchestrator.composer.cve_matcher import match as cve_match, pick_orchestrated
from clab_builder.orchestrator.composer.scenario_assembler import ScenarioAssembler
from clab_builder.orchestrator.composer.sysfield_exporter import SysFieldExporter


class ScenarioPipeline:
    """Template → Match → Assemble pipeline"""

    def __init__(
        self,
        templates_dir: str = "templates",
        atoms_dir: str = "data/atoms",
    ):
        self.templates_dir = templates_dir
        self.atoms_dir = atoms_dir
        self.template_loader = TemplateLoader(templates_dir=templates_dir)
        self.atom_loader = AtomLoader(atoms_dir=atoms_dir)
        self.assembler = ScenarioAssembler(self.template_loader)

    def generate(
        self,
        template_name: str,
        cve_ids: Optional[list[str]] = None,
        scenario_name: Optional[str] = None,
        output_dir: str = "data/scenarios",
        seed: Optional[int] = None,
    ) -> dict:
        """生成完整场景

        Args:
            template_name: 拓扑模板名
            cve_ids: 指定 CVE ID 列表 (None = 自动匹配)
            scenario_name: 场景名
            output_dir: 输出目录
            seed: 随机种子 (用于可复现)

        Returns:
            assembled scenario dict (同 ScenarioAssembler.assemble 的返回值)
        """
        import random
        if seed is not None:
            random.seed(seed)

        template = self.template_loader.load(template_name)
        all_atoms = self.atom_loader.load_all_verified(single_service_only=True)

        if not all_atoms:
            raise ValueError("No verified single-service atoms available")

        # Determine atoms for each injection point
        selected_atoms = []
        used_cves = []

        total_injections = len(template.injection_points)
        for index, ip in enumerate(template.injection_points):
            if cve_ids and len(cve_ids) > len(selected_atoms):
                # User specified CVEs — load directly
                cve_id = cve_ids[len(selected_atoms)]
                atom = self.atom_loader.load(cve_id)
                if not atom.verified:
                    raise ValueError(f"Atom {cve_id} is not verified")
                selected_atoms.append(atom)
                used_cves.append(cve_id)
            else:
                # Auto-match from library
                matched = cve_match(ip, all_atoms, exclude=used_cves)
                if not matched:
                    raise ValueError(
                        f"No matching atom for injection_point '{ip.id}' "
                        f"(required: mitre={ip.required_mitre}, "
                        f"vuln_category={ip.required_vuln_category})"
                    )
                picked = pick_orchestrated(
                    matched,
                    injection_point=ip,
                    index=index,
                    total=total_injections,
                    count=1,
                )
                selected_atoms.append(picked[0])
                used_cves.append(picked[0].cve_id)

        # Assemble
        scenario = self.assembler.assemble(
            template_name=template_name,
            atoms=selected_atoms,
            scenario_name=scenario_name,
            atoms_dir=self.atoms_dir,
        )

        # Write output
        scenario_dir = self.assembler.write_output(scenario, output_dir)
        sysfield_playbook = SysFieldExporter(atoms_dir=self.atoms_dir).export(scenario_dir)
        scenario["sysfield_playbook"] = sysfield_playbook

        return scenario

    def batch(
        self,
        template_name: str,
        count: int = 5,
        output_dir: str = "data/scenarios",
        seed: Optional[int] = None,
    ) -> list[dict]:
        """批量生成多个场景 (避免重复 CVE 组合)

        Returns:
            list of scenario dicts
        """
        import random
        if seed is not None:
            random.seed(seed)

        results = []
        seen_hashes = set()

        for i in range(count):
            try:
                scenario = self.generate(
                    template_name=template_name,
                    scenario_name=f"{template_name}-batch-{i+1:03d}",
                    output_dir=output_dir,
                )
                if scenario["hash"] not in seen_hashes:
                    seen_hashes.add(scenario["hash"])
                    results.append(scenario)
            except ValueError:
                continue  # skip if no match

        return results
