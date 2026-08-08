"""Tests for Scenario Assembler"""

import json
import pytest
import yaml
from pathlib import Path

from clab_builder.shared.models.atom import (
    AtomConfig, VulnCategory, MitrePhase, ServiceRole,
    ExploitComplexity, AttackMethod, ServiceInfo, FlagInjection,
    ServiceStartup, NetworkRequirements, PostExploit, PivotCapability,
    RuntimeSpec,
    RuntimeBuildSpec,
    RuntimeStatus,
    SourceBundle,
    ExploitAccess,
)
from clab_builder.shared.models.template import InjectionPoint
from clab_builder.orchestrator.composer.scenario_assembler import (
    ScenarioAssembler, _generate_flag, _generate_scenario_hash, _zone_bridge_name,
)
from clab_builder.orchestrator.composer.template_loader import TemplateLoader


def _make_atom(cve_id="CVE-TEST-0001", ports=None, requires_pivot_host=False) -> AtomConfig:
    return AtomConfig(
        cve_id=cve_id,
        category="test",
        docker_image="vulhub/test:latest",
        ports=ports or [8080],
        services=[ServiceInfo(name="web", image="vulhub/test:latest")],
        vuln_category=VulnCategory.RCE,
        primary_mitre_phase=MitrePhase.INITIAL_ACCESS,
        service_role=ServiceRole.WEB_APPLICATION,
        exploit_complexity=ExploitComplexity.SIMPLE,
        attack_method=AttackMethod.SINGLE_REQUEST,
        flag_injection=FlagInjection(method="env_var", env_var_name="FLAG"),
        service_startup=ServiceStartup(wait_seconds=5),
        exploit_access=ExploitAccess(
            required_service=(
                {"protocol": "postgres", "port": 5432}
                if 5432 in (ports or [8080])
                else {"protocol": "http", "port": (ports or [8080])[0]}
            )
        ),
        post_exploit=PostExploit(
            pivot_capability=(
                PivotCapability.FULL_TOOLBOX
                if requires_pivot_host
                else PivotCapability.NONE
            ),
            requires_pivot_host=requires_pivot_host,
        ),
        verified=True,
    )


class TestHelpers:
    def test_generate_flag_format(self):
        flag = _generate_flag()
        assert flag.startswith("flag{")
        assert flag.endswith("}")
        # 16 bytes hex = 32 chars + 5 for "flag{" + 1 for "}" = 38
        assert len(flag) == 38

    def test_generate_flag_unique(self):
        flags = {_generate_flag() for _ in range(20)}
        assert len(flags) == 20

    def test_scenario_hash_deterministic(self):
        h1 = _generate_scenario_hash("test", ["CVE-001", "CVE-002"])
        h2 = _generate_scenario_hash("test", ["CVE-002", "CVE-001"])  # order-independent
        assert h1 == h2

    def test_scenario_hash_different_scenarios(self):
        h1 = _generate_scenario_hash("test1", ["CVE-001"])
        h2 = _generate_scenario_hash("test2", ["CVE-001"])
        assert h1 != h2


class TestAssemblerDMZSimple:
    """用真实的 dmz_simple 模板测试"""

    @pytest.fixture
    def assembler(self):
        loader = TemplateLoader(templates_dir="templates")
        return ScenarioAssembler(loader)

    def test_assemble_single_cve(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])

        assert result["template"] == "dmz_simple"
        assert "target-1" in result["clab"]["topology"]["nodes"]
        assert len(result["injections"]) == 1
        assert result["injections"][0]["cve_id"] == "CVE-TEST-0001"
        assert result["injections"][0]["flag"].startswith("flag{")

    def test_objectives_have_private_and_agent_views(self, assembler):
        atoms = [
            _make_atom("CVE-1", ports=[80]),
            _make_atom("CVE-2", ports=[8080]),
            _make_atom("CVE-3", ports=[5432]),
        ]
        result = assembler.assemble(
            "enterprise_3tier", atoms, scenario_name="objective-contract"
        )

        private = result["objectives"]
        public = result["agent_objectives"]
        assert [item["id"] for item in private] == ["read-customer-records"]
        assert private[0]["target_node"] == "target-3"
        assert private[0]["actor_node"] == "target-2"
        assert private[0]["reference_command"]
        assert private[0]["success_pattern"]
        assert private[0]["asset_variant"] == "postgresql"
        assert public[0]["id"] == "read-customer-records"
        assert public[0]["target_node"] == "target-3"
        assert public[0]["actor_node"] == "target-2"
        assert "reference_command" not in public[0]
        assert "success_pattern" not in public[0]
        assert public[0]["service_family"] == "postgresql"
        assert "CVELAB-CANARY" not in json.dumps(public[0])
        assert result["ground_truth"]["objectives"] == private

    def test_clab_has_attacker_and_target(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        nodes = result["clab"]["topology"]["nodes"]
        assert "attacker" in nodes
        assert "edge-router" in nodes
        assert "target-1" in nodes

    def test_target_linked_to_router(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        links = result["clab"]["topology"]["links"]
        # Should have at least the base link + 1 target link
        assert len(links) >= 2
        target_links = [l for l in links if "target-1" in str(l)]
        assert len(target_links) == 1

    def test_target_has_flag_env(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        assert "FLAG" in target["env"]
        assert target["env"]["FLAG"].startswith("flag{")

    def test_target_has_docker_image(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        assert target["image"] == "vulhub/test:latest"

    def test_multi_target_zone_uses_router_bridge(self, assembler):
        """Multiple targets in one zone form one shared router-side LAN."""
        atoms = [
            _make_atom("CVE-TEST-WEB", ports=[8080]),
            _make_atom("CVE-TEST-DB", ports=[5432]),
        ]
        result = assembler.assemble("dmz_dual", atoms, scenario_name="bridge-dual")
        router = result["ip_allocations"]["edge-router"]
        bridge = router["bridges"][0]
        base = result["ansible_base"]

        assert bridge["interfaces"] == ["eth2", "eth3"]
        assert bridge["address"] == "192.168.100.1/24"
        assert bridge["name"] == _zone_bridge_name("edge-router", "dmz")
        assert "eth2" not in {key for key in router if key not in {"routes", "bridges"}}
        assert "eth3" not in {key for key in router if key not in {"routes", "bridges"}}
        target_ips = {
            result["ip_allocations"][name]["eth1"]
            for name in ("target-1", "target-2")
        }
        assert len(target_ips) == 2
        assert all(ip.startswith("192.168.100.") for ip in target_ips)
        assert result["ip_allocations"]["target-1"]["gateway"] == "192.168.100.1"
        assert result["ip_allocations"]["target-2"]["gateway"] == "192.168.100.1"
        assert {
            check["target_node"] for check in result["ground_truth"]["network_policy_checks"]
        } == {"target-1", "target-2"}
        normalized_base = " ".join(base.split())
        assert normalized_base.index(f"ip link add name {bridge['name']} type bridge") < normalized_base.index(
            f"ip link set eth2 master {bridge['name']}"
        ) < normalized_base.index(f"ip addr replace {bridge['address']} dev {bridge['name']}")
        assert f"ip addr replace {bridge['address']} dev eth2" not in normalized_base
        assert f"ip addr replace {bridge['address']} dev eth3" not in normalized_base

    def test_single_target_zone_keeps_point_to_point_gateway(self, assembler):
        result = assembler.assemble("dmz_simple", [_make_atom()], scenario_name="bridge-single")
        router = result["ip_allocations"]["edge-router"]
        assert "bridges" not in router
        assert router["eth2"] == "192.168.100.1/24"
        assert "type bridge" not in result["ansible_base"]

    def test_router_zone_bridge_names_are_stable_and_distinct(self):
        assert _zone_bridge_name("edge-router", "dmz") == _zone_bridge_name(
            "edge-router", "dmz"
        )
        assert _zone_bridge_name("edge-router", "dmz") != _zone_bridge_name(
            "edge-router", "app"
        )
        assert len(_zone_bridge_name("long-router-name", "long-zone-name")) <= 15

    def test_runtime_spec_is_rendered_into_node(self, assembler):
        atom = _make_atom()
        atom.runtime_spec = RuntimeSpec(
            ports=[8080],
            services=[],
            command="php -S 0.0.0.0:8080",
            environment={"DB_PASSWORD": "postgres"},
        )
        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        assert target["cmd"] == "php -S 0.0.0.0:8080"
        assert target["env"]["DB_PASSWORD"] == "postgres"
        assert target["env"]["FLAG"].startswith("flag{")

    @pytest.mark.parametrize("agent_context", ["l0", "l1"])
    def test_level_attacker_has_no_source_bundle_mounts(self, assembler, agent_context):
        atom = _make_atom()
        atom.source_bundle = SourceBundle(poc_materials=["poc.py", "id_rsa"])

        result = assembler.assemble("dmz_simple", [atom], agent_context=agent_context)
        attacker = result["clab"]["topology"]["nodes"]["attacker"]

        assert not any("/vulhub/" in bind for bind in attacker.get("binds", []))

    def test_declared_dockerfile_becomes_runtime_build_manifest(self, assembler, tmp_path):
        atom = _make_atom("CVE-BUILD-0001")
        atom.source_bundle = SourceBundle(dockerfiles=["source_bundle/Dockerfile"])
        bundle = tmp_path / atom.cve_id / "source_bundle"
        bundle.mkdir(parents=True)
        (bundle / "Dockerfile").write_text("FROM test:latest\n")

        result = assembler.assemble(
            "dmz_simple", [atom], atoms_dir=str(tmp_path), scenario_name="build-contract"
        )
        assert len(result["runtime_builds"]) == 1
        build = result["runtime_builds"][0]
        assert build["cve_id"] == atom.cve_id
        assert result["clab"]["topology"]["nodes"]["target-1"]["image"] == build["image"]
        selection = result["runtime_images"][0]
        assert selection["selection"] == "legacy_source_bundle_build"
        assert selection["fallback_reason"] == "runtime_status_not_requested"

    @pytest.mark.parametrize(
        ("runtime_status", "runtime_image", "verification_status", "expected_image", "selection", "reason"),
        [
            (RuntimeStatus.READY, "cvelab-runtime-ready:1", "ready",
             "cvelab-runtime-ready:1", "runtime_image", ""),
            (RuntimeStatus.FAILED, "cvelab-runtime-failed:1", "failed",
             "vulhub/test:latest", "source_image", "runtime_status_failed"),
            (RuntimeStatus.UNSUPPORTED, None, "unsupported",
             "vulhub/test:latest", "source_image", "runtime_status_unsupported"),
            (RuntimeStatus.NOT_REQUESTED, None, "missing",
             "vulhub/test:latest", "source_image", "runtime_status_not_requested"),
        ],
        ids=["ready", "failed", "unsupported", "legacy"],
    )
    def test_runtime_image_selection_states(
        self, assembler, runtime_status, runtime_image, verification_status,
        expected_image, selection, reason,
    ):
        """Range consumes only an Atom runtime image with two ready records."""
        atom = _make_atom()
        atom.runtime_spec = RuntimeSpec(
            ports=[8080],
            source_image="vulhub/test:latest",
            runtime_image=runtime_image,
            runtime_status=runtime_status,
            runtime_build=RuntimeBuildSpec(
                base_image_digest="sha256:base",
                generated_hash="runtime-build-hash",
            ),
        )
        atom.verification["runtime_verification"] = {
            "status": verification_status,
            "runtime_image_digest": "sha256:runtime",
        }

        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        record = result["runtime_images"][0]

        assert target["image"] == expected_image
        assert record["selected_image"] == expected_image
        assert record["selection"] == selection
        assert record["fallback_reason"] == reason
        assert record["source_image"] == "vulhub/test:latest"
        assert record["base_image_digest"] == "sha256:base"
        assert record["runtime_build_generated_hash"] == "runtime-build-hash"

    def test_ready_runtime_without_ready_verification_falls_back(self, assembler):
        atom = _make_atom()
        atom.runtime_spec = RuntimeSpec(
            ports=[8080], source_image="vulhub/test:latest",
            runtime_image="cvelab-runtime-unverified:1",
            runtime_status=RuntimeStatus.READY,
        )
        result = assembler.assemble("dmz_simple", [atom])
        record = result["runtime_images"][0]
        assert record["selection"] == "source_image"
        assert record["fallback_reason"] == "runtime_verification_missing"

    def test_runtime_image_selection_is_written_to_scenario_metadata(self, assembler, tmp_path):
        atom = _make_atom()
        atom.runtime_spec = RuntimeSpec(
            ports=[8080], source_image="vulhub/test:latest",
            runtime_image="cvelab-runtime-ready:1",
            runtime_status=RuntimeStatus.READY,
            runtime_build=RuntimeBuildSpec(
                base_image_digest="sha256:base",
                generated_hash="runtime-build-hash",
            ),
        )
        atom.verification["runtime_verification"] = {
            "status": "ready", "runtime_image_digest": "sha256:runtime",
        }
        result = assembler.assemble("dmz_simple", [atom], scenario_name="runtime-meta")
        out_dir = assembler.write_output(result, str(tmp_path))

        meta = yaml.safe_load(Path(out_dir, "scenario.yaml").read_text())
        assert meta["runtime_images"] == result["runtime_images"]
        assert meta["runtime_images"][0]["selected_image"] == "cvelab-runtime-ready:1"

    def test_ready_runtime_without_digest_falls_back(self, assembler):
        atom = _make_atom()
        atom.runtime_spec = RuntimeSpec(
            ports=[8080], source_image="vulhub/test:latest",
            runtime_image="cvelab-runtime-unpinned:1",
            runtime_status=RuntimeStatus.READY,
            runtime_build=RuntimeBuildSpec(
                base_image_digest="sha256:base",
                generated_hash="runtime-build-hash",
            ),
        )
        atom.verification["runtime_verification"] = {"status": "ready"}

        result = assembler.assemble("dmz_simple", [atom])

        record = result["runtime_images"][0]
        assert record["selection"] == "source_image"
        assert record["fallback_reason"] == "runtime_image_digest_missing"

    def test_asset_service_contract_rejects_incompatible_atom(self, assembler):
        atom = _make_atom("CVE-SSH-0001", ports=[22])
        atom.exploit_access = atom.exploit_access.model_copy(
            update={"required_service": {"protocol": "ssh", "port": 22}}
        )
        atoms = [_make_atom("CVE-1"), _make_atom("CVE-2"), atom]
        with pytest.raises(ValueError, match="no compatible service variant"):
            assembler.assemble("enterprise_3tier", atoms)
        template = assembler.template_loader.load("enterprise_3tier")
        assert not assembler.slot_asset_compatible(template, template.injection_points[2], atom)

    def test_asset_variants_select_elasticsearch_without_agent_role_relabel(self, assembler):
        elasticsearch = _make_atom("CVE-ES-0001", ports=[9200])
        elasticsearch.docker_image = "vulhub/elasticsearch:1.4.2"
        elasticsearch.runtime_spec = RuntimeSpec(
            ports=[9200], source_image="vulhub/elasticsearch:1.4.2"
        )
        elasticsearch.exploit_access = ExploitAccess(
            required_service={"protocol": "http", "port": 9200}
        )
        result = assembler.assemble(
            "enterprise_3tier",
            [_make_atom("CVE-1", ports=[80]), _make_atom("CVE-2", ports=[8080]), elasticsearch],
            scenario_name="elasticsearch-variant",
        )

        binding = result["resolved_asset_bindings"]["customer-records"]
        assert binding["variant_id"] == "elasticsearch"
        assert binding["service_family"] == "elasticsearch"
        assert "9200/customers" in result["asset_setup"]
        assert "9200/customers" in result["objectives"][0]["reference_command"]
        assert result["agent_objectives"][0]["agent_hint"]
        assert "CVELAB-CANARY" not in result["agent_objectives"][0]["agent_hint"]
        assert "reference_command" not in result["agent_objectives"][0]
        asset_setup = yaml.safe_load(result["asset_setup"])
        customer_task = next(
            task for play in asset_setup for task in play["tasks"]
            if task["name"] == "setup_command customer-records"
        )
        assert customer_task["ansible.builtin.shell"].startswith(
            "timeout 20s docker exec "
        )
        assert customer_task["retries"] == 18
        assert customer_task["delay"] == 10
        assert customer_task["until"].endswith(".rc == 0")

    def test_legacy_compose_runtime_is_migrated_without_cve_special_case(self, assembler, tmp_path):
        atom = _make_atom("CVE-LEGACY-0001")
        atom.runtime_spec = RuntimeSpec(ports=[8080], services=[])
        atom.source_bundle = SourceBundle(compose_file="source_bundle/docker-compose.yml")
        bundle = tmp_path / atom.cve_id / "source_bundle"
        bundle.mkdir(parents=True)
        (bundle / "docker-compose.yml").write_text(yaml.safe_dump({
            "services": {
                "web": {
                    "image": "vulhub/test:latest",
                    "command": "php -S 0.0.0.0:8080",
                    "environment": {"DB_PASSWORD": "postgres"},
                }
            }
        }))

        result = assembler.assemble(
            "dmz_simple", [atom], atoms_dir=str(tmp_path), scenario_name="legacy-runtime"
        )
        target = result["clab"]["topology"]["nodes"]["target-1"]
        assert target["cmd"] == "php -S 0.0.0.0:8080"
        assert target["env"]["DB_PASSWORD"] == "postgres"

    def test_ground_truth_contains_service_readiness_probe(self, assembler):
        atom = _make_atom(ports=[8080])
        result = assembler.assemble("dmz_simple", [atom])
        probes = result["ground_truth"]["attack_path"][0]["readiness_probes"]
        assert any(p["probe_type"] == "tcp" and p["target"] == "8080" for p in probes)

    def test_target_has_binds_for_flag(self, assembler):
        """Target should have CLab binds including flag file"""
        atom = _make_atom(ports=[8080, 8443])
        result = assembler.assemble("dmz_simple", [atom])
        target = result["clab"]["topology"]["nodes"]["target-1"]
        # No host port mapping — everything internal
        assert "ports" not in target
        # FLAG file should be bind-mounted
        assert "binds" in target
        flag_bind = [b for b in target["binds"] if b.endswith(":/flag.txt")]
        assert len(flag_bind) == 1

    def test_file_flag_uses_atom_declared_path(self, assembler):
        atom = _make_atom()
        atom.flag_injection = FlagInjection(method="file", file_path="/flag")
        atom.flag_spec = None
        # Re-run model normalization for the manually replaced field.
        atom.flag_spec = atom.model_validate(atom.model_dump()).flag_spec
        result = assembler.assemble("dmz_simple", [atom])

        target = result["clab"]["topology"]["nodes"]["target-1"]
        assert any(bind.endswith(":/flag") for bind in target["binds"])
        assert result["ground_truth"]["attack_path"][0]["flag_hint"] == "file:/flag"

    def test_cve_setup_generated(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        assert len(result["cve_setup"]) == 1
        setup = result["cve_setup"][0]
        # cve-setup runs on localhost (init files already mounted via CLab binds)
        assert setup["hosts"] == "localhost"
        assert len(setup["tasks"]) >= 1  # at least the wait task
        assert any("Probe TCP 8080" in task["name"] for task in setup["tasks"])
        assert all(task.get("failed_when") is False for task in setup["tasks"] if "Probe TCP" in task["name"])
        probe = next(task for task in setup["tasks"] if "Probe TCP" in task["name"])
        assert probe["register"] == "readiness_target_1_8080"
        # Readiness probe must poll until the port listens (retries:18 delay:10
        # = 180s window) so slow-start services are ready before asset_setup
        # writes the canary. See WORK_PROGRESS_REPORT 2026-07-21.
        assert probe["until"] == "readiness_target_1_8080.rc == 0"
        assert probe["retries"] == 18
        assert probe["delay"] == 10

    def test_ground_truth_structure(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        gt = result["ground_truth"]
        assert gt["scenario"]
        assert gt["template"] == "dmz_simple"
        assert len(gt["attack_path"]) == 1
        step = gt["attack_path"][0]
        assert step["step"] == 1
        assert step["cve_id"] == "CVE-TEST-0001"
        assert step["flag"].startswith("flag{")

    def test_scenario_hash_present(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom])
        assert len(result["hash"]) == 16

    def test_custom_scenario_name(self, assembler):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="my-scenario")
        assert result["name"] == "my-scenario"
        assert result["clab"]["name"] == "my-scenario"

    def test_base_yaml_generation_preserves_route_metadata(self, assembler):
        atoms = [
            _make_atom("CVE-TEST-0001"),
            _make_atom("CVE-TEST-0002"),
            _make_atom("CVE-TEST-0003", ports=[5432]),
        ]
        result = assembler.assemble("enterprise_3tier", atoms)

        router_allocations = [
            config
            for node, config in result["ip_allocations"].items()
            if node.endswith("-router")
        ]
        assert any(config.get("routes") for config in router_allocations)

    def test_ground_truth_contains_dependency_and_capability_metadata(self, assembler):
        atoms = [
            _make_atom("CVE-TEST-0001"),
            _make_atom("CVE-TEST-0002"),
            _make_atom("CVE-TEST-0003", ports=[5432]),
        ]
        result = assembler.assemble("enterprise_3tier", atoms, scenario_name="dag-meta")

        path = result["ground_truth"]["attack_path"]
        assert path[0]["kill_chain_phase"] == "entry"
        assert path[1]["depends_on"] == ["dmz-web"]
        assert path[1]["depends_on_nodes"] == ["target-1"]
        assert path[1]["execution_host"] == "dmz-web"
        assert path[1]["execution_host_node"] == "target-1"
        assert path[2]["required_assets"] == []
        assert path[0]["mitre_phase"] == "initial_access"
        assert "provides" in path[0]

    def test_ground_truth_contains_runtime_network_policy_checks(self, assembler):
        atoms = [
            _make_atom("CVE-TEST-0001"),
            _make_atom("CVE-TEST-0002"),
            _make_atom("CVE-TEST-0003", ports=[5432]),
        ]
        result = assembler.assemble("enterprise_3tier", atoms, scenario_name="policy-meta")

        checks = result["ground_truth"]["network_policy_checks"]
        assert any(
            check["source_node"] == "target-1"
            and check["target_node"] == "target-2"
            and check["expected_reachable"] is True
            for check in checks
        )
        assert any(
            check["source_node"] == "attacker"
            and check["target_node"] == "target-2"
            and check["expected_reachable"] is False
            for check in checks
        )

    def test_generated_network_setup_does_not_mask_address_failures(self, assembler):
        result = assembler.assemble("dmz_simple", [_make_atom()], scenario_name="fail-fast")

        assert "ip addr replace" in result["ansible_base"]
        assert "&& ip link set" in result["ansible_base"]
        assert "2>/dev/null; ip link set" not in result["ansible_base"]
        assert "docker exec -u 0" in result["ansible_base"]
        assert "command -v ip" in result["ansible_base"]
        assert "apt-get install -y -qq iproute2" in result["ansible_base"]
        assert "sudo -n nsenter" not in result["ansible_base"]

    def test_pivot_host_atom_generates_host_and_service_nodes(self, assembler):
        atom = _make_atom(requires_pivot_host=True)
        result = assembler.assemble("dmz_simple", [atom], scenario_name="pivot-test")

        nodes = result["clab"]["topology"]["nodes"]
        assert nodes["target-1"]["image"] == "cvelab-pivot-base:latest"
        assert nodes["target-1"]["cmd"] == "sleep infinity"
        assert nodes["target-1-service"]["image"] == "vulhub/test:latest"
        assert (
            nodes["target-1-service"]["network-mode"]
            == "container:clab-pivot-test-target-1"
        )
        assert nodes["target-1-service"]["env"]["FLAG"].startswith("flag{")

    def test_pivot_host_link_and_ip_allocation_use_host_node(self, assembler):
        atom = _make_atom(requires_pivot_host=True)
        result = assembler.assemble("dmz_simple", [atom], scenario_name="pivot-test")

        links = result["clab"]["topology"]["links"]
        assert any("target-1:eth1" in link["endpoints"] for link in links)
        assert not any("target-1-service:eth1" in str(link) for link in links)
        assert "target-1" in result["ip_allocations"]
        assert "target-1-service" not in result["ip_allocations"]

        step = result["ground_truth"]["attack_path"][0]
        assert step["target_node"] == "target-1"
        assert step["service_node"] == "target-1-service"
        assert step["requires_pivot_host"] is True

    def test_intermediate_weak_atom_does_not_auto_generate_pivot_host(self, assembler):
        atoms = [
            _make_atom("CVE-TEST-0001"),
            _make_atom("CVE-TEST-0002"),
        ]
        result = assembler.assemble("dmz_dual", atoms, scenario_name="auto-pivot")

        nodes = result["clab"]["topology"]["nodes"]
        assert nodes["target-1"]["image"] == "vulhub/test:latest"
        assert "target-1-service" not in nodes
        assert nodes["target-2"]["image"] == "vulhub/test:latest"

        first_step = result["ground_truth"]["attack_path"][0]
        second_step = result["ground_truth"]["attack_path"][1]
        assert first_step["service_node"] == "target-1"
        assert first_step["requires_pivot_host"] is False
        assert second_step["service_node"] == "target-2"
        assert second_step["requires_pivot_host"] is False


class TestAssemblerOutput:
    """测试 write_output"""

    @pytest.fixture
    def assembler(self):
        loader = TemplateLoader(templates_dir="templates")
        return ScenarioAssembler(loader)

    def test_write_output_creates_files(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-output")
        out_dir = assembler.write_output(result, str(tmp_path))

        assert Path(out_dir, "clab.yaml").exists()
        assert Path(out_dir, "ground_truth.json").exists()
        assert Path(out_dir, "scenario.yaml").exists()
        assert Path(out_dir, "ansible", "base.yaml").exists()
        assert Path(out_dir, "ansible", "cve-setup.yaml").exists()

    def test_written_clab_is_valid_yaml(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-yaml")
        out_dir = assembler.write_output(result, str(tmp_path))

        clab = yaml.safe_load(Path(out_dir, "clab.yaml").read_text())
        assert "topology" in clab
        assert "target-1" in clab["topology"]["nodes"]

    def test_written_ground_truth_is_valid_json(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-gt")
        out_dir = assembler.write_output(result, str(tmp_path))

        gt = json.loads(Path(out_dir, "ground_truth.json").read_text())
        assert gt["template"] == "dmz_simple"
        assert len(gt["attack_path"]) == 1

    def test_written_scenario_metadata(self, assembler, tmp_path):
        atom = _make_atom()
        result = assembler.assemble("dmz_simple", [atom], scenario_name="test-meta")
        out_dir = assembler.write_output(result, str(tmp_path))

        meta = yaml.safe_load(Path(out_dir, "scenario.yaml").read_text())
        assert meta["name"] == "test-meta"
        assert meta["template"] == "dmz_simple"
        assert len(meta["injections"]) == 1

    def test_enterprise_asset_playbooks_are_written(self, assembler, tmp_path):
        atoms = [
            _make_atom("CVE-TEST-0001"),
            _make_atom("CVE-TEST-0002"),
            _make_atom("CVE-TEST-0003", ports=[5432]),
        ]
        result = assembler.assemble("enterprise_3tier", atoms, scenario_name="asset-meta")
        out_dir = assembler.write_output(result, str(tmp_path))

        setup = Path(out_dir, "ansible", "asset-setup.yaml")
        verify = Path(out_dir, "ansible", "asset-verify.yaml")
        assert setup.exists()
        assert verify.exists()
        assert "clab-asset-meta-target-3" in setup.read_text()
        assert "CVELAB-CANARY" in verify.read_text()
