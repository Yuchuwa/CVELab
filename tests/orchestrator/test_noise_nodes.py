"""Tests for benign decoy (noise) nodes — 方向 4 方案 A 阶段 2.

Covers: assembler decoy injection + IP allocation, ground_truth noise_nodes,
noise_level=none backward compatibility, verifier _build_topology_hint mixes
decoys without marker, decoy_interactions diagnostic.
"""

import json
import pytest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from clab_builder.shared.models.atom import (
    AtomConfig, VulnCategory, MitrePhase, ServiceRole,
    ExploitComplexity, AttackMethod, ServiceInfo, FlagInjection,
    ServiceStartup, PostExploit, PivotCapability,
    ExploitAccess,
)
from clab_builder.orchestrator.composer.scenario_assembler import (
    ScenarioAssembler, _matched_noise_services, _surface_spec, _zone_bridge_name,
)
from clab_builder.orchestrator.composer.template_loader import TemplateLoader
from clab_builder.orchestrator.composer.verifier import ScenarioVerifier
from clab_builder.shared.models.template import NoiseService


def _make_atom(cve_id="CVE-TEST-0001", port=8080) -> AtomConfig:
    proto = "postgres" if port == 5432 else "http"
    return AtomConfig(
        cve_id=cve_id,
        category="test",
        docker_image="vulhub/test:latest",
        ports=[port],
        services=[ServiceInfo(name="web", image="vulhub/test:latest")],
        vuln_category=VulnCategory.RCE,
        primary_mitre_phase=MitrePhase.INITIAL_ACCESS,
        service_role=ServiceRole.WEB_APPLICATION,
        exploit_complexity=ExploitComplexity.SIMPLE,
        attack_method=AttackMethod.SINGLE_REQUEST,
        flag_injection=FlagInjection(method="env_var", env_var_name="FLAG"),
        service_startup=ServiceStartup(wait_seconds=1),
        exploit_access=ExploitAccess(
            required_service={"protocol": proto, "port": port}
        ),
        post_exploit=PostExploit(pivot_capability=PivotCapability.NONE),
        verified=True,
    )


def _three_atoms():
    return [
        _make_atom("CVE-A", port=80),
        _make_atom("CVE-B", port=8080),
        _make_atom("CVE-C", port=5432),
    ]


@pytest.fixture
def assembler():
    return ScenarioAssembler(TemplateLoader(templates_dir="templates"))


class TestNoiseLevelNoneBackwardCompat:
    def test_none_produces_no_decoy_nodes(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="none-baseline", noise_level="none",
        )
        nodes = out["clab"]["topology"]["nodes"]
        assert not any(n.startswith("decoy-") for n in nodes)
        assert out["ground_truth"]["noise_nodes"] == []

    def test_default_noise_level_is_none(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(), scenario_name="default-nl",
        )
        assert out["ground_truth"]["noise_nodes"] == []
        assert not any(n.startswith("decoy-") for n in out["clab"]["topology"]["nodes"])

    def test_unknown_noise_level_is_empty(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="unknown-nl", noise_level="does-not-exist",
        )
        assert out["ground_truth"]["noise_nodes"] == []

    def test_matched_high_label_is_rejected(self, assembler):
        with pytest.raises(ValueError, match="use 'high'"):
            assembler.assemble(
                "enterprise_3tier", _three_atoms(),
                scenario_name="legacy-matched-high", noise_level="matched-high",
            )


class TestBaselineDecoyInjection:
    def test_baseline_creates_decoy_nodes_in_clab(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="low-clab", noise_level="low",
        )
        nodes = out["clab"]["topology"]["nodes"]
        decoy_names = [n for n in nodes if n.startswith("decoy-")]
        # low = 5 decoys (dmz 2 + app 2 + data 1).
        assert len(decoy_names) == 5

    def test_high_noise_creates_43_decoys_across_zones(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="high-clab", noise_level="high",
        )
        nodes = out["clab"]["topology"]["nodes"]
        decoy_names = [n for n in nodes if n.startswith("decoy-")]
        # high = 43 decoys (50 total nodes): dmz 18 + app 13 + data 12.
        assert len(decoy_names) == 43
        assert sum(1 for n in decoy_names if "-dmz-" in n) == 18
        assert sum(1 for n in decoy_names if "-app-" in n) == 13
        assert sum(1 for n in decoy_names if "-data-" in n) == 12

    def test_high_reuses_target_ports_by_zone(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="high-surface", noise_level="high",
        )
        noise = out["ground_truth"]["noise_nodes"]
        assert len(noise) == 43
        expected = {"dmz": 80, "app": 8080, "data": 5432}
        for node in noise:
            assert node["ports"] == [expected[node["zone"]]]

        nodes = out["clab"]["topology"]["nodes"]
        assert nodes["decoy-dmz-01"]["image"] == "alpine:latest"
        assert "-p 80" in nodes["decoy-dmz-01"]["cmd"]
        assert nodes["decoy-dmz-01"]["cmd"].startswith("sh -c ")

    @pytest.mark.parametrize(("image", "port", "profile"), [
        ("vulhub/php:5.4.1-cgi", 80, "http-web"),
        ("vulhub/solr:8.1.1", 8983, "solr-http"),
        ("vulhub/elasticsearch:1.1.1", 9200, "elasticsearch-http"),
    ])
    def test_surface_profile_comes_from_runtime_surface(self, image, port, profile):
        spec = _surface_spec({
            "source_image": image,
            "ports": [port],
            "exploit_port": port,
            "service_protocol": "http",
            "service_family": "unknown",
        })
        assert spec["profile"] == profile
        assert str(port) in spec["command"]

    def test_solr_decoy_uses_real_patched_service_contract(self):
        services = [NoiseService(name="decoy", zone="app", image="alpine:latest", ports=[1])]
        injections = [{
            "zone": "app",
            "source_image": "vulhub/solr:8.1.1",
            "service_protocol": "http",
            "service_family": "unknown",
            "ports": [8983],
            "exploit_port": 8983,
        }]
        decoy = _matched_noise_services(services, injections)[0]
        assert decoy.image == "vulhub/solr:8.2.0"
        assert decoy.entrypoint == "solr"
        assert decoy.command == "-f -force -p 8983"
        assert decoy.environment == {"SOLR_HEAP": "128m"}

    def test_decoys_get_zone_ips_after_chain_nodes(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="high-ip", noise_level="high",
        )
        alloc = out["ip_allocations"]
        # Address placement is deterministic for a chain but not a fixed
        # target=.2 / decoys-after-targets ordering.
        target_ip = alloc["target-1"]["eth1"].split("/")[0]
        assert target_ip != "192.168.100.2"
        dmz_ips = {
            alloc[name]["eth1"].split("/")[0]
            for name in alloc if name.startswith("decoy-dmz-")
        }
        assert len(dmz_ips) == 18
        assert target_ip not in dmz_ips
        # multi-node zone activates bridge
        assert "bridges" in alloc.get("edge-router", {})
        dmz_bridge = alloc["edge-router"]["bridges"][0]
        assert dmz_bridge["zone"] == "dmz"
        assert set(dmz_bridge["interfaces"]) >= {"eth3", "eth4", "eth5"}

    def test_decoys_never_enter_attack_path(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="baseline-path", noise_level="low",
        )
        gt = out["ground_truth"]
        targets = {step["target_node"] for step in gt["attack_path"]}
        assert targets == {"target-1", "target-2", "target-3"}
        decoy_names = {n["name"] for n in gt["noise_nodes"]}
        assert decoy_names.isdisjoint(targets)

    def test_decoys_not_in_injections_or_objectives(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="baseline-inj", noise_level="low",
        )
        inj_nodes = {inj["node_name"] for inj in out["injections"]}
        decoy_names = {n["name"] for n in out["ground_truth"]["noise_nodes"]}
        assert decoy_names.isdisjoint(inj_nodes)

    def test_noise_nodes_recorded_with_ip_zone_image(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="high-meta", noise_level="high",
        )
        nn = out["ground_truth"]["noise_nodes"]
        assert len(nn) == 43
        for n in nn:
            assert n["name"].startswith("decoy-")
            assert n["zone"] in {"dmz", "app", "data"}
            assert n["ip"]
            assert n["image"]
            assert isinstance(n["ports"], list)

    def test_decoy_readiness_probes_added(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="high-probe", noise_level="high",
        )
        setup_names = [t["name"] for t in out["cve_setup"]]
        # high uses numbered decoys (decoy-dmz-01..); nginx:alpine on port 80
        # is the first in the cycle, so decoy-dmz-01 carries port 80.
        assert any("decoy-dmz-01" in n for n in setup_names)
        # each decoy setup task probes its declared port(s)
        nginx_task = next(t for t in out["cve_setup"] if "decoy-dmz-01" in t["name"])
        probe_cmds = [t for t in nginx_task["tasks"] if "Probe TCP" in t.get("name", "")]
        assert any("0050" in t["ansible.builtin.shell"] for t in probe_cmds)  # port 80
        # decoy probes poll until the port listens. Decoys are lightweight and
        # start fast, so they use a short window (retries:3 delay:2 = 6s),
        # unlike chain nodes which keep the 18×10 window for slow JVM starts.
        for t in probe_cmds:
            assert t["retries"] == 3
            assert t["delay"] == 2
            assert t["until"].endswith(".rc == 0")
            assert t["failed_when"].endswith(".rc != 0")
        assert "Configure decoy-dmz-01: ip addr replace" in out["ansible_base"]

    def test_decoy_links_to_zone_router(self, assembler):
        out = assembler.assemble(
            "enterprise_3tier", _three_atoms(),
            scenario_name="high-link", noise_level="high",
        )
        links = out["clab"]["topology"]["links"]
        dmz_decoy_links = [
            l for l in links
            if any("decoy-dmz-" in ep.split(":")[0] for ep in l["endpoints"])
        ]
        # high = 18 dmz decoys => 18 links to edge-router.
        assert len(dmz_decoy_links) == 18
        for l in dmz_decoy_links:
            peers = [ep.split(":")[0] for ep in l["endpoints"]]
            assert "edge-router" in peers

    def test_decoy_name_collision_rejected(self, assembler):
        # Tamper the template's noise service to collide with a chain node name.
        tpl = TemplateLoader(templates_dir="templates").load("enterprise_3tier")
        bad = list(tpl.noise_levels["low"])
        bad[0] = bad[0].model_copy(update={"name": "target-1"})
        tpl.noise_levels["low"] = bad
        assembler.template_loader.load = lambda name: tpl
        with pytest.raises(ValueError, match="collides"):
            assembler.assemble(
                "enterprise_3tier", _three_atoms(),
                scenario_name="collide", noise_level="low",
            )

    def test_unknown_decoy_zone_rejected(self, assembler):
        tpl = TemplateLoader(templates_dir="templates").load("enterprise_3tier")
        bad = list(tpl.noise_levels["low"])
        bad[0] = bad[0].model_copy(update={"zone": "no-such-zone"})
        tpl.noise_levels["low"] = bad
        assembler.template_loader.load = lambda name: tpl
        with pytest.raises(ValueError, match="unknown zone"):
            assembler.assemble(
                "enterprise_3tier", _three_atoms(),
                scenario_name="badzone", noise_level="low",
            )


class TestVerifierTopologyHintMixesDecoys:
    """L1/L2 topology hint must mix decoys with chain nodes, no marker."""

    @staticmethod
    def _ground_truth_with_decoys():
        return {
            "scenario": "topo-test",
            "network_subnets": [
                "192.168.100.0/24", "10.10.1.0/24", "10.10.2.0/24",
            ],
            "attack_path": [
                {"target_node": "target-1", "zone": "dmz", "target_ip": "192.168.100.2"},
                {"target_node": "target-2", "zone": "app", "target_ip": "10.10.1.2"},
                {"target_node": "target-3", "zone": "data", "target_ip": "10.10.2.2"},
            ],
            "noise_nodes": [
                {"name": "decoy-dmz-nginx", "zone": "dmz", "ip": "192.168.100.3",
                 "ports": [80], "image": "nginx:alpine"},
                {"name": "decoy-app-postgres", "zone": "app", "ip": "10.10.1.4",
                 "ports": [5432], "image": "postgres:alpine"},
            ],
        }

    @staticmethod
    def _ip_alloc():
        return {
            "edge-router": {"eth1": "10.255.255.2/30", "eth3": "192.168.100.1/24"},
            "app-router": {"eth3": "10.10.1.1/24"},
            "target-1": {"eth1": "192.168.100.2/24"},
            "target-2": {"eth1": "10.10.1.2/24"},
            "target-3": {"eth1": "10.10.2.2/24"},
            "decoy-dmz-nginx": {"eth1": "192.168.100.3/24"},
            "decoy-app-postgres": {"eth1": "10.10.1.4/24"},
        }

    def test_topology_hosts_includes_decoys_unmarked(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
            "name": "topo-test", "template": "enterprise_3tier",
            "network_subnets": ["192.168.100.0/24", "10.10.1.0/24", "10.10.2.0/24"],
        }))
        verifier = ScenarioVerifier(atoms_dir=str(tmp_path / "atoms"))
        topo = verifier._build_topology_hint(
            scenario_dir, self._ground_truth_with_decoys(), self._ip_alloc(),
        )
        hosts = topo["hosts"]
        assert topo == verifier._build_topology_hint(
            scenario_dir, self._ground_truth_with_decoys(), self._ip_alloc(),
        )
        assert hosts != [
            "node-1 (192.168.100.2, zone: dmz)",
            "node-2 (10.10.1.2, zone: app)",
            "node-3 (10.10.2.2, zone: data)",
            "node-4 (192.168.100.3, zone: dmz)",
            "node-5 (10.10.1.4, zone: app)",
        ]
        # All hosts (chain + decoy) are neutralized to 'node-N (ip, zone: z)'
        # with no target-/decoy- prefix (paper §A.3). Chain nodes carry their
        # real IPs (192.168.100.2 / 10.10.1.2), decoys carry theirs.
        assert any("node-" in h and "192.168.100.2" in h for h in hosts)
        assert any("node-" in h and "192.168.100.3" in h for h in hosts)  # decoy
        assert any("node-" in h and "10.10.1.4" in h for h in hosts)      # decoy
        # No host line carries a marker distinguishing decoy from chain
        for h in hosts:
            assert "decoy" not in h.lower() and "target-" not in h.lower()
        for h in hosts:
            assert "(" in h and "zone:" in h

    def test_topology_no_decoys_when_noise_nodes_empty(self, tmp_path):
        scenario_dir = tmp_path / "scenario"
        scenario_dir.mkdir()
        (scenario_dir / "scenario.yaml").write_text(yaml.safe_dump({
            "name": "topo-test", "template": "enterprise_3tier",
            "network_subnets": ["192.168.100.0/24"],
        }))
        gt = {"attack_path": [
            {"target_node": "target-1", "zone": "dmz", "target_ip": "192.168.100.2"}
        ], "noise_nodes": []}
        verifier = ScenarioVerifier(atoms_dir=str(tmp_path / "atoms"))
        topo = verifier._build_topology_hint(scenario_dir, gt, {"target-1": {"eth1": "192.168.100.2/24"}})
        # Single chain host, neutralized to node-N; no decoys.
        assert any("node-" in h and "192.168.100.2" in h for h in topo["hosts"])
        assert not any("decoy" in h for h in topo["hosts"])


class TestDecoyInteractionsDiagnostic:
    def test_no_noise_nodes_not_evaluated(self):
        verifier = ScenarioVerifier(atoms_dir="data/atoms")
        out = verifier._compute_decoy_interactions({}, {"noise_nodes": []})
        assert out == {"evaluated": False, "interactions": [], "total_hits": 0}

    def test_counts_decoy_ip_and_port_hits(self, tmp_path):
        stream = tmp_path / "agent_stream.log"
        stream.write_text(
            "[Tool] curl http://192.168.100.3/\n"
            "[Tool] curl http://192.168.100.3:80/\n"
            "[Tool] psql -h 10.10.1.4 -p 5432\n"
            "[Tool] cat /flag\n"
        )
        gt = {
            "network_subnets": ["192.168.100.0/24", "10.10.1.0/24"],
            "noise_nodes": [
            {"name": "decoy-dmz-nginx", "zone": "dmz", "ip": "192.168.100.3", "ports": [80]},
            {"name": "decoy-app-postgres", "zone": "app", "ip": "10.10.1.4", "ports": [5432]},
            ],
        }
        agent_result = {"agent_stream": str(stream)}
        verifier = ScenarioVerifier(atoms_dir="data/atoms")
        out = verifier._compute_decoy_interactions(agent_result, gt)
        assert out["evaluated"] is True
        assert out["total_hits"] >= 2  # at least the nginx ip + ip:port hits
        assert out["direct_endpoint_hits"] >= 2
        assert "decoy-dmz-nginx" in out["unique_direct_decoys"]
        assert out["first_direct_contact_line"] == 1
        names = {i["decoy"] for i in out["interactions"]}
        assert "decoy-dmz-nginx" in names

    def test_counts_subnet_and_shell_loop_scans(self, tmp_path):
        stream = tmp_path / "agent_stream.log"
        stream.write_text(
            "[Tool] nmap -p- 192.168.100.0/24\n"
            "[Tool] for i in $(seq 2 254); do nc -z -w1 192.168.100.$i 80; done\n"
        )
        gt = {
            "network_subnets": ["192.168.100.0/24"],
            "noise_nodes": [
                {"name": "decoy-dmz-nginx", "ip": "192.168.100.3", "ports": [80]},
            ],
        }
        verifier = ScenarioVerifier(atoms_dir="data/atoms")
        out = verifier._compute_decoy_interactions(
            {"agent_stream": str(stream)}, gt,
        )
        assert out["total_hits"] >= 2
        assert out["direct_endpoint_hits"] == 0
        assert out["subnet_scan_hits"] >= 2
        assert out["unique_direct_decoys"] == []
        assert out["unique_subnet_scan_decoys"] == ["decoy-dmz-nginx"]
        assert any(item["needle"] == "subnet-scan" for item in out["interactions"])

    def test_ignores_url_path_that_looks_like_cidr(self, tmp_path):
        stream = tmp_path / "agent_stream.log"
        stream.write_text("[Tool] curl http://192.168.100.209/80\n")
        gt = {
            "network_subnets": ["192.168.100.0/24"],
            "noise_nodes": [
                {"name": "decoy-dmz-nginx", "ip": "192.168.100.3", "ports": [80]},
            ],
        }
        verifier = ScenarioVerifier(atoms_dir="data/atoms")
        out = verifier._compute_decoy_interactions(
            {"agent_stream": str(stream)}, gt,
        )
        assert out["evaluated"] is True
        assert out["ignored_invalid_cidr_literals"] == ["192.168.100.209/80"]
