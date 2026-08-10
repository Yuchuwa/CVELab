"""Scenario — 主入口，串联 Template → Match → Assemble pipeline"""

from typing import Optional
from pathlib import Path

from clab_builder.orchestrator.composer.template_loader import TemplateLoader
from clab_builder.orchestrator.composer.atom_loader import AtomLoader
from clab_builder.orchestrator.composer.cve_matcher import match_kill_chain, pick_random
from clab_builder.orchestrator.composer.capability_closure import (
    close_capabilities,
    seed_capabilities,
)
from clab_builder.orchestrator.composer.scenario_assembler import ScenarioAssembler
from clab_builder.orchestrator.composer.sysfield_exporter import SysFieldExporter
from clab_builder.atomizer.output.sysfield_playbook import SysFieldPlaybookGenerator
from clab_builder.shared.models.atom import CapabilityType
from clab_builder.shared.models.artifact_contracts import (
    ScenarioManifestV1,
    normalize_agent_context,
)
from clab_builder.shared.models.exploit_guide import ExploitGuide, validate_exploit_guide
from clab_builder.core.paper_workflow import DependencyPlanner, Generator, IncompatibilityStore


class ScenarioPipeline:
    """Template → Match → Assemble pipeline"""

    def __init__(
        self,
        templates_dir: str = "templates",
        atoms_dir: str = "data/atoms",
        default_validation_mode: str = "guided_agent",
        incompatibility_path: str | None = None,
        atom_admission_mode: str = "completed",
    ):
        if default_validation_mode not in {"guided_agent", "sysfield"}:
            raise ValueError("default_validation_mode must be guided_agent or sysfield")
        if atom_admission_mode not in {"completed", "legacy_verified"}:
            raise ValueError(
                "atom_admission_mode must be completed or legacy_verified"
            )
        self.templates_dir = templates_dir
        self.atoms_dir = atoms_dir
        self.default_validation_mode = default_validation_mode
        self.atom_admission_mode = atom_admission_mode
        self.incompatibility_store = (
            IncompatibilityStore(incompatibility_path)
            if incompatibility_path else None
        )
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
        validation_mode: Optional[str] = None,
        agent_context: str = "guided",
        noise_level: str = "none",
        composition_mode: str = "legacy",
    ) -> dict:
        """生成完整场景

        Args:
            template_name: 拓扑模板名
            cve_ids: 指定 CVE ID 列表 (None = 自动匹配)
            scenario_name: 场景名
            output_dir: 输出目录
            seed: 随机种子 (用于可复现)
            agent_context: Agent 上下文 (guided/no_guide/no_hint/l0/l1/l2)，
                控制 clab.yaml 中 attacker 的 PoC 材料挂载策略
            noise_level: 噪音档位 (模板 ``noise_levels`` 的 key，默认 none)，
                控制是否在 zone LAN 内插入良性 decoy 节点。正交于 agent_context。

        Returns:
            assembled scenario dict (同 ScenarioAssembler.assemble 的返回值)
        """
        import random
        if seed is not None:
            random.seed(seed)

        validation_mode = validation_mode or self.default_validation_mode
        if validation_mode not in {"guided_agent", "sysfield"}:
            raise ValueError("validation_mode must be guided_agent or sysfield")
        if composition_mode not in {"legacy", "paper"}:
            raise ValueError("composition_mode must be legacy or paper")
        agent_context = normalize_agent_context(agent_context)

        template = self.template_loader.load(template_name)
        if composition_mode == "paper":
            template_errors = Generator.validate(template)
            if template_errors:
                raise ValueError("Template rejected by Generator gate: " + "; ".join(template_errors))
        if cve_ids:
            # Fail explicit production requests with the Atom's canonical
            # lifecycle and blockers before considering automatic candidates.
            for cve_id in cve_ids:
                self._load_admitted_atom(cve_id)
        completed_atoms = self._load_admitted_atoms(single_service_only=True)
        all_atoms = [
            atom for atom in completed_atoms
            if self._range_usable_atom(atom, validation_mode=validation_mode)
        ]

        if not all_atoms:
            admission = (
                "completed"
                if self.atom_admission_mode == "completed"
                else "legacy verified"
            )
            if validation_mode == "guided_agent" and completed_atoms:
                raise ValueError(
                    f"No {admission} single-service atoms with ready exploit guides; "
                    "backfill/review guides or use --validation-mode sysfield"
                )
            raise ValueError(f"No {admission} single-service atoms available")

        # Determine atoms for each injection point
        selected_atoms = []
        used_cves = []
        resolved_upstream = {}
        resolved_closures = {}
        available_assets: set[str] = set()

        # The legacy path is retained for old experiment manifests.  The
        # paper path uses the shared dependency planner, so single-scenario
        # generation and matrix generation consume the same compatibility
        # gate, prefix state, backtracking, and incompatibility semantics.
        if composition_mode == "paper":
            planner_atoms = all_atoms
            if cve_ids:
                requested = set(cve_ids)
                planner_atoms = [atom for atom in all_atoms if atom.cve_id in requested]
                missing = requested - {atom.cve_id for atom in planner_atoms}
                if missing:
                    raise ValueError("Requested atoms are unavailable: " + ", ".join(sorted(missing)))
            candidates = DependencyPlanner(
                incompatibilities=self.incompatibility_store
            ).compose(template, planner_atoms, max_candidates=1)
            if not candidates:
                raise ValueError("No dependency-compatible attack-chain candidate")
            chosen = candidates[0]
            selected_atoms = [
                self._load_admitted_atom(chosen.bindings[slot.id])
                for slot in template.injection_points
            ]
            used_cves = [atom.cve_id for atom in selected_atoms]
            for slot, atom in zip(template.injection_points, selected_atoms):
                resolved_upstream[slot.id] = atom
                closure = close_capabilities(
                    seed_capabilities(atom, host_scope=slot.id), template.assets
                )
                resolved_closures[slot.id] = closure
                available_assets.update(closure.assets)

        for ip in ([] if composition_mode == "paper" else template.injection_points):
            missing_dependencies = [
                dependency for dependency in ip.depends_on
                if dependency not in resolved_upstream
            ]
            if missing_dependencies:
                raise ValueError(
                    f"Injection point '{ip.id}' has unresolved dependencies: "
                    + ", ".join(missing_dependencies)
                )

            # A dependent slot is reachable only when every upstream slot has a
            # verified network vantage.  This is deliberately checked before
            # selecting the downstream atom; otherwise the range becomes a
            # list of independent exploits with a decorative ordering.
            for dependency in ip.depends_on:
                closure = resolved_closures[dependency]
                if not any(
                    fact.type == CapabilityType.NETWORK_VANTAGE
                    and fact.host_scope == dependency
                    for fact in closure.capabilities
                ):
                    raise ValueError(
                        f"Injection point '{ip.id}' is not reachable from '{dependency}': "
                        "upstream atom has no verified network_vantage"
                    )

            if cve_ids and len(cve_ids) > len(selected_atoms):
                # User specified CVEs — load directly
                cve_id = cve_ids[len(selected_atoms)]
                atom = self._load_admitted_atom(cve_id)
                if cve_id in used_cves:
                    raise ValueError(f"Atom {cve_id} is used more than once in the scenario")
                # Narrow authoritative gate mirroring _range_usable_atom: only
                # block guide-integrity failure or an explicitly failed
                # environment. Fixable data gaps stay admissible.
                from clab_builder.shared.atom_qualification import qualify_atom
                atom_dir = Path(self.atoms_dir) / cve_id
                qr = qualify_atom(atom, atom_dir)
                if qr.checks.get("guide", {}).get("ok") is False:
                    raise ValueError(
                        f"Atom {cve_id} guide integrity failed: "
                        f"{'; '.join(qr.checks['guide'].get('reasons', []))}"
                    )
                if qr.checks.get("environment", {}).get("environment_ready") is False:
                    raise ValueError(
                        f"Atom {cve_id} has environment_ready=false"
                    )
                # 槽位兼容性校验：显式指定的 CVE 也必须满足槽位约束，
                # 否则编排出的场景不符合模板语义。
                compatible = match_kill_chain(
                    ip,
                    [atom],
                    resolved_upstream=resolved_upstream,
                    available_assets=available_assets,
                )
                compatible = self._keep_chain_capable_atoms(
                    ip, compatible, template
                )
                compatible = [
                    item for item in compatible
                    if self.assembler.slot_asset_compatible(template, ip, item)
                ]
                if not compatible:
                    raise ValueError(
                        f"Atom {cve_id} does not satisfy injection_point '{ip.id}' "
                        f"constraints (required_capabilities={ip.required_capabilities}, "
                        f"required_mitre={ip.required_mitre}, "
                        f"vuln_category={ip.required_vuln_category}, "
                        f"service_role={ip.required_service_role}, "
                        f"service_access={ip.required_service_access}, "
                        f"atom_service_access={atom.exploit_access.required_service})"
                    )
                selected_atoms.append(atom)
                used_cves.append(cve_id)
            else:
                # Auto-match from library
                matched = match_kill_chain(
                    ip,
                    all_atoms,
                    exclude=used_cves,
                    resolved_upstream=resolved_upstream,
                    available_assets=available_assets,
                )
                matched = self._keep_chain_capable_atoms(ip, matched, template)
                matched = [
                    item for item in matched
                    if self.assembler.slot_asset_compatible(template, ip, item)
                ]
                if not matched:
                    raise ValueError(
                        f"No matching atom for injection_point '{ip.id}' "
                        f"(required: capabilities={ip.required_capabilities}, "
                        f"mitre={ip.required_mitre}, "
                        f"vuln_category={ip.required_vuln_category}, "
                        f"service_access={ip.required_service_access})"
                    )
                picked = pick_random(matched, count=1)
                selected_atoms.append(picked[0])
                used_cves.append(picked[0].cve_id)

            resolved_upstream[ip.id] = selected_atoms[-1]
            closure = close_capabilities(
                seed_capabilities(selected_atoms[-1], host_scope=ip.id),
                template.assets,
            )
            resolved_closures[ip.id] = closure
            available_assets.update(closure.assets)

        resolved_asset_bindings = self.assembler.resolve_asset_bindings(template, selected_atoms)

        if validation_mode == "guided_agent":
            self._validate_guided_chain(
                template, selected_atoms, available_assets, resolved_asset_bindings
            )

        # Assemble
        scenario = self.assembler.assemble(
            template_name=template_name,
            atoms=selected_atoms,
            scenario_name=scenario_name,
            atoms_dir=self.atoms_dir,
            resolved_asset_bindings=resolved_asset_bindings,
            agent_context=agent_context,
            noise_level=noise_level,
        )

        # Write output
        scenario_dir = self.assembler.write_output(scenario, output_dir)
        scenario["validation_mode"] = validation_mode
        if validation_mode == "sysfield":
            sysfield_playbook = SysFieldExporter(atoms_dir=self.atoms_dir).export(scenario_dir)
            scenario["sysfield_playbook"] = sysfield_playbook
        else:
            scenario["exploit_guides"] = self._write_guides(
                scenario_dir, template, selected_atoms
            )

            # This is a build-time report only.  It resolves the logical
            # execution contract without pretending that tools exist inside
            # the deployed foothold; the verifier performs that runtime check.
            guide_diagnostics = self._guide_static_compatibility(
                template, selected_atoms
            )
            scenario["guide_advisories"] = guide_diagnostics
            # Migration alias for scenario readers written before the Guide
            # advisory/integrity split.
            scenario["guide_compatibility"] = guide_diagnostics

        # Persist mode and guide manifest in scenario.yaml without changing the
        # assembler's topology/ground-truth format.
        import yaml
        scenario_meta_path = Path(scenario_dir) / "scenario.yaml"
        scenario_meta = yaml.safe_load(scenario_meta_path.read_text()) or {}
        scenario_meta["validation_mode"] = validation_mode
        if scenario.get("exploit_guides"):
            scenario_meta["exploit_guides"] = scenario["exploit_guides"]
        if scenario.get("guide_compatibility"):
            scenario_meta["guide_compatibility"] = scenario["guide_compatibility"]
        if scenario.get("guide_advisories"):
            scenario_meta["guide_advisories"] = scenario["guide_advisories"]
        scenario_meta = ScenarioManifestV1.model_validate(scenario_meta).model_dump(
            mode="json"
        )
        scenario_meta_path.write_text(
            yaml.safe_dump(scenario_meta, sort_keys=False, allow_unicode=True)
        )

        return scenario

    def _load_admitted_atom(self, cve_id: str):
        """Load one production Atom or use explicitly requested compatibility."""
        if self.atom_admission_mode == "completed":
            atom = self.atom_loader.load_completed(cve_id)
        else:
            atom = self.atom_loader.load(cve_id)
            if not atom.verified:
                raise ValueError(f"Legacy Atom {cve_id} is not verified")
        if len(atom.services) > 1:
            raise ValueError(
                f"Atom {cve_id} declares {len(atom.services)} services; "
                "the single-service Range slot contract does not support it"
            )
        return atom

    def _load_admitted_atoms(self, *, single_service_only: bool):
        """Load the configured admission pool; completed is the default."""
        if self.atom_admission_mode == "completed":
            return self.atom_loader.load_all_completed(
                single_service_only=single_service_only
            )
        return self.atom_loader.load_all_verified(
            single_service_only=single_service_only
        )

    def _guide_static_compatibility(self, template, atoms: list) -> dict:
        """Report Guide contracts that can be checked before deployment.

        v1 guides remain usable in migration mode, but their global tool list
        has no execution scope and is therefore explicitly marked legacy.  A
        v2 guide receives alignment advisories here; actual tool/module
        availability belongs to the post-deploy verifier.
        """
        entries = []
        for injection_point, atom in zip(template.injection_points, atoms):
            guide = self._load_atom_guide(atom.cve_id)
            if guide is None:
                entries.append({
                    "injection_point": injection_point.id,
                    "cve_id": atom.cve_id,
                    "status": "invalid",
                    "checks": [{"status": "failed", "reason": "guide_unavailable"}],
                })
                continue
            if guide.version < 2:
                advisories = self._guide_alignment_diagnostics(
                    injection_point, atom, guide
                )
                entries.append({
                    "injection_point": injection_point.id,
                    "cve_id": atom.cve_id,
                    "guide_version": guide.version,
                    "status": "unknown_legacy",
                    "checks": [{
                        "status": "unknown",
                        "reason": "guide_has_no_step_execution_scope",
                    }],
                    "advisories": advisories,
                })
                continue

            advisories = self._guide_alignment_diagnostics(
                injection_point, atom, guide
            )
            checks = []
            for step in guide.steps:
                execution = step.execution
                checks.append({
                    "step_id": step.id,
                    "scope": execution.scope if execution else "",
                    "tools": [tool.model_dump(mode="json") for tool in execution.tools]
                    if execution else [],
                    "materials": [material.model_dump(mode="json") for material in execution.materials]
                    if execution else [],
                    "status": "ok" if execution else "failed",
                })
            entries.append({
                "injection_point": injection_point.id,
                "cve_id": atom.cve_id,
                "guide_version": guide.version,
                "status": "warnings" if advisories else "static_compatible",
                "checks": checks,
                "advisories": advisories,
            })

        statuses = {entry["status"] for entry in entries}
        if "invalid" in statuses:
            overall = "invalid"
        elif "unknown_legacy" in statuses:
            overall = "unknown_legacy"
        elif "warnings" in statuses:
            overall = "warnings"
        else:
            overall = "static_compatible"
        return {
            "evaluated": True,
            "overall_status": overall,
            "entries": entries,
        }

    @staticmethod
    def _guide_alignment_diagnostics(injection_point, atom, guide) -> list[dict]:
        """Report Guide/Atom differences without making them Range gates.

        Atom metadata, template contracts and the generated topology remain
        authoritative.  These diagnostics explain why a native-environment
        Guide may need adaptation in the rebuilt Range.
        """
        diagnostics = []
        atom_privileges = str(
            getattr(atom.exploit_access, "privileges_required", "none")
        )
        guide_privileges = str(guide.preconditions.privileges_required or "none")
        if atom_privileges != guide_privileges:
            diagnostics.append({
                "code": "privilege_mismatch",
                "atom": atom_privileges,
                "guide": guide_privileges,
            })

        required_service = getattr(atom.exploit_access, "required_service", {}) or {}
        protocol = str(required_service.get("protocol", ""))
        port = required_service.get("port")
        if protocol and guide.target.protocol and protocol != guide.target.protocol:
            diagnostics.append({
                "code": "protocol_mismatch",
                "atom": protocol,
                "guide": guide.target.protocol,
            })
        if port is not None and guide.target.port is not None:
            try:
                port_mismatch = int(port) != int(guide.target.port)
            except (TypeError, ValueError):
                port_mismatch = True
            if port_mismatch:
                diagnostics.append({
                    "code": "port_mismatch",
                    "atom": port,
                    "guide": guide.target.port,
                })

        if (
            injection_point.required_service_role
            and guide.target.service_role not in injection_point.required_service_role
        ):
            diagnostics.append({
                "code": "service_role_mismatch",
                "required": list(injection_point.required_service_role),
                "guide": guide.target.service_role,
            })

        verified_grants = [
            grant for grant in getattr(atom, "capability_grants", [])
            if getattr(
                getattr(grant, "evidence_level", ""),
                "value",
                getattr(grant, "evidence_level", ""),
            ) == "verified"
        ]
        verified_types = {
            capability.value for capability in atom.verified_capability_types
        }
        guide_types = set(guide.post_exploit.capabilities)
        for capability in sorted(guide_types - verified_types):
            diagnostics.append({
                "code": "capability_unverified",
                "capability": capability,
            })
        for capability in sorted(verified_types - guide_types):
            diagnostics.append({
                "code": "capability_omitted",
                "capability": capability,
            })

        principals = {
            str(getattr(grant, "principal", "")) for grant in verified_grants
        }
        if (
            guide.post_exploit.principal != "unknown"
            and principals
            and guide.post_exploit.principal not in principals
        ):
            diagnostics.append({
                "code": "principal_mismatch",
                "atom": sorted(principals),
                "guide": guide.post_exploit.principal,
            })
        return diagnostics

    def _range_usable_atom(self, atom, *, validation_mode: str = "guided_agent") -> bool:
        """Filter completed atoms by the selected Range validation contract.

        Lifecycle completion is authoritative. This method retains the
        validation-artifact checks specific to the requested Range mode.
        """
        if validation_mode == "guided_agent":
            if self._load_atom_guide(atom.cve_id) is None:
                return False
        else:
            path = Path(self.atoms_dir) / atom.cve_id / "playbook" / "sysfield.yaml"
            if not path.exists():
                return False
            try:
                SysFieldPlaybookGenerator.validate(path.read_text())
            except (OSError, ValueError):
                return False

        # These checks are redundant with completion for guided mode but keep
        # this helper safe when called independently by diagnostics.
        from clab_builder.shared.atom_qualification import qualify_atom
        atom_dir = Path(self.atoms_dir) / atom.cve_id
        qr = qualify_atom(atom, atom_dir)
        if qr.checks.get("guide", {}).get("ok") is False:
            return False
        if qr.checks.get("environment", {}).get("environment_ready") is False:
            return False
        return True

    def _load_atom_guide(self, cve_id: str) -> ExploitGuide | None:
        """Load and validate the guide referenced by an Atom."""
        atom_path = Path(self.atoms_dir) / cve_id / "atom.yaml"
        if not atom_path.exists():
            return None
        import yaml
        try:
            atom_data = yaml.safe_load(atom_path.read_text()) or {}
            ref = atom_data.get("exploit_guide") or {}
            if isinstance(ref, dict) and ref.get("status", "ready") != "ready":
                return None
            guide_path = ref.get("path", "exploit_guide.yaml") if isinstance(ref, dict) else str(ref)
            if Path(guide_path).is_absolute() or ".." in Path(guide_path).parts:
                return None
            path = Path(self.atoms_dir) / cve_id / guide_path
            if not path.is_file():
                return None
            guide = ExploitGuide.model_validate(yaml.safe_load(path.read_text()) or {})
            if guide.cve_id != cve_id:
                return None
            bundle = atom_data.get("source_bundle") or {}
            materials = set(bundle.get("poc_materials") or [])
            for material in materials:
                material_path = Path(self.atoms_dir) / cve_id / material
                if not material_path.is_file():
                    return None
            forbidden = [str(atom_data.get("flag_value") or "")]
            validate_exploit_guide(
                guide,
                source_bundle_materials=materials,
                forbidden_values=forbidden,
            )
            return guide
        except (OSError, ValueError, TypeError, yaml.YAMLError):
            return None

    def _validate_guided_chain(
        self,
        template,
        atoms: list,
        available_assets: set[str],
        resolved_asset_bindings: dict[str, dict],
    ) -> None:
        """Validate the semantic inputs required by Guided Agent execution.

        This is intentionally deterministic: it does not claim that an Agent
        will succeed, but rejects a Range whose guides, capabilities, assets,
        or objective declarations are internally inconsistent.
        """
        objective_ids = set()
        for objective in template.objectives:
            objective_id = str(objective.id or "").strip() or (
                f"{objective.asset}-{objective.validation}"
            )
            if objective_id in objective_ids:
                raise ValueError(f"guided Range has duplicate objective id {objective_id!r}")
            objective_ids.add(objective_id)
            asset_binding = resolved_asset_bindings.get(objective.asset, {})
            variant_id = asset_binding.get("variant_id", "")
            if variant_id:
                assertions = [
                    item for item in objective.assertion_variants
                    if item.asset_variant == variant_id
                ]
                has_assertion = len(assertions) == 1
            else:
                has_assertion = bool(objective.reference_command and objective.success_pattern)
            if not has_assertion:
                raise ValueError(
                    f"guided Range objective {objective_id!r} requires "
                    "one resolved reference_command and success_pattern"
                )
            if objective.verification_mode not in {"agent_evidence"}:
                raise ValueError(
                    f"guided Range objective {objective_id!r} has unsupported "
                    f"verification_mode {objective.verification_mode!r}"
                )

        assets_by_id = {asset.id: asset for asset in template.assets}
        required_asset_ids = {
            asset_id
            for injection_point in template.injection_points
            for asset_id in injection_point.required_assets
        }
        required_asset_ids.update(objective.asset for objective in template.objectives)
        for asset_id in required_asset_ids:
            asset = assets_by_id.get(asset_id)
            binding = resolved_asset_bindings.get(asset_id, {})
            if not asset or not binding.get("setup_command") or not binding.get("verify_command"):
                raise ValueError(
                    f"Guided Range asset {asset_id!r} requires setup_command and verify_command"
                )

        previous_atoms: dict[str, object] = {}
        for injection_point, atom in zip(template.injection_points, atoms):
            guide = self._load_atom_guide(atom.cve_id)
            if guide is None:
                raise ValueError(
                    f"Atom {atom.cve_id} has no valid ready exploit guide"
                )

            required_capabilities = {
                capability.value for capability in injection_point.required_capabilities
            }
            atom_capabilities = {
                capability.value for capability in atom.verified_capability_types
            }
            if not required_capabilities.issubset(atom_capabilities):
                raise ValueError(
                    f"Atom {atom.cve_id} lacks required verified capabilities: "
                    + ", ".join(sorted(required_capabilities - atom_capabilities))
                )

            for dependency in injection_point.depends_on:
                upstream = previous_atoms.get(dependency)
                if upstream is None:
                    raise ValueError(
                    f"Guided chain dependency {dependency!r} is unresolved"
                    )

            if injection_point.required_assets and not set(injection_point.required_assets).issubset(
                available_assets
            ):
                missing = sorted(set(injection_point.required_assets) - available_assets)
                raise ValueError(
                    f"Guided chain is missing required assets for {injection_point.id}: "
                    + ", ".join(missing)
                )

            previous_atoms[injection_point.id] = atom

    def _write_guides(self, scenario_dir: str, template, atoms: list) -> list[dict]:
        """Copy selected Atom guides into the generated Range."""
        import yaml
        guide_dir = Path(scenario_dir) / "exploit_guides"
        guide_dir.mkdir(parents=True, exist_ok=True)
        manifest = []
        for injection_point, atom in zip(template.injection_points, atoms):
            guide = self._load_atom_guide(atom.cve_id)
            if guide is None:
                raise ValueError(
                    f"Atom {atom.cve_id} has no valid exploit guide for guided_agent mode"
                )
            filename = f"{injection_point.id}.yaml"
            path = guide_dir / filename
            path.write_text(yaml.safe_dump(
                guide.model_dump(mode="json"), sort_keys=False, allow_unicode=True
            ))
            manifest.append({
                "injection_point": injection_point.id,
                "cve_id": atom.cve_id,
                "path": f"exploit_guides/{filename}",
                "depends_on": list(injection_point.depends_on),
            })
        return manifest

    @staticmethod
    def _keep_chain_capable_atoms(ip, atoms, template):
        """Keep upstream candidates that can actually make dependent slots reachable."""
        has_dependents = any(
            ip.id in other.depends_on for other in template.injection_points
        )
        if not has_dependents:
            return atoms

        reachable = []
        for atom in atoms:
            closure = close_capabilities(seed_capabilities(atom, host_scope=ip.id), template.assets)
            if any(
                fact.type == CapabilityType.NETWORK_VANTAGE
                and fact.host_scope == ip.id
                for fact in closure.capabilities
            ):
                reachable.append(atom)
        return reachable

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
