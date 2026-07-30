"""Tests for template model, loader, and all templates"""

import pytest
import yaml
from pathlib import Path

from clab_builder.shared.models.template import (
    TopologyTemplate, ZoneDef, RouterDef, IsolationRule,
    InjectionPoint, NoiseService,
)
from clab_builder.orchestrator.composer.template_loader import TemplateLoader


# ── Model validation tests ──────────────────────────────

class TestTemplateModel:
    def test_injection_point_defaults(self):
        ip = InjectionPoint(
            id="test-1", zone="dmz",
            required_mitre=["initial_access"],
            required_vuln_category=["RCE"],
        )
        assert ip.count == 1
        assert ip.required_service_role is None

    def test_isolation_rule_alias(self):
        rule = IsolationRule(**{"from": "attacker", "to": "dmz", "action": "accept"})
        assert rule.from_zone == "attacker"
        assert rule.to_zone == "dmz"

    def test_zone_def(self):
        z = ZoneDef(subnet="10.0.0.0/24", type="dmz")
        assert z.type == "dmz"

    def test_router_def(self):
        r = RouterDef(connects=["attacker", "dmz"])
        assert r.image == "frrouting/frr:latest"
        assert r.connects == ["attacker", "dmz"]

    def test_noise_service_defaults(self):
        n = NoiseService(name="x", zone="dmz", image="nginx:alpine")
        assert n.ports == []
        assert n.command == ""
        assert n.environment == {}

    def test_noise_service_full_fields(self):
        n = NoiseService(
            name="y", zone="app", image="postgres:alpine",
            ports=[5432], command="postgres",
            environment={"POSTGRES_PASSWORD": "decoy"},
        )
        assert n.ports == [5432]
        assert n.command == "postgres"
        assert n.environment == {"POSTGRES_PASSWORD": "decoy"}


# ── Template loader tests ───────────────────────────────

class TestTemplateLoader:
    @pytest.fixture
    def loader(self):
        return TemplateLoader(templates_dir="templates")

    def test_list_available(self, loader):
        templates = loader.list_available()
        assert "dmz_simple" in templates

    def test_load_dmz_simple(self, loader):
        tpl = loader.load("dmz_simple")
        assert tpl.name == "dmz_simple"
        assert "dmz" in tpl.zones
        assert tpl.zones["dmz"].type == "dmz"
        assert "edge-router" in tpl.routers
        assert len(tpl.injection_points) == 1
        assert tpl.injection_points[0].id == "dmz-target-1"
        assert tpl.injection_points[0].zone == "dmz"

    def test_load_clab_base(self, loader):
        clab = loader.load_clab_base("dmz_simple")
        assert "topology" in clab
        assert "attacker" in clab["topology"]["nodes"]
        assert "edge-router" in clab["topology"]["nodes"]

    def test_load_ansible_base(self, loader):
        ansible = loader.load_ansible_base("dmz_simple")
        assert "edge-router" in ansible
        assert "ip_forward" in ansible

    def test_load_nonexistent_template(self, loader):
        with pytest.raises(FileNotFoundError, match="Template not found"):
            loader.load("nonexistent_template")

    def test_injection_point_matching_fields(self, loader):
        """验证 injection_point 的匹配字段完整"""
        tpl = loader.load("dmz_simple")
        ip = tpl.injection_points[0]
        assert "initial_access" in ip.required_mitre or "execution" in ip.required_mitre
        assert "RCE" in ip.required_vuln_category
        assert ip.count >= 1

    def test_isolation_rules_parsed(self, loader):
        tpl = loader.load("dmz_simple")
        assert len(tpl.isolation_rules) >= 1
        rule = tpl.isolation_rules[0]
        assert rule.from_zone == "attacker"
        assert rule.to_zone == "dmz"
        assert rule.action == "accept"


# ── Template create/load roundtrip ──────────────────────

class TestTemplateRoundtrip:
    def test_create_and_load(self, tmp_path):
        """创建一个模板目录，然后加载验证"""
        tpl_dir = tmp_path / "test_tpl"
        tpl_dir.mkdir()
        (tpl_dir / "ansible").mkdir()

        template_data = {
            "name": "test_tpl",
            "description": "Test template",
            "zones": {"dmz": {"subnet": "10.0.0.0/24", "type": "dmz"}},
            "routers": {"r1": {"connects": ["attacker", "dmz"]}},
            "injection_points": [
                {
                    "id": "target-1",
                    "zone": "dmz",
                    "required_mitre": ["initial_access"],
                    "required_vuln_category": ["RCE"],
                    "count": 1,
                }
            ],
        }
        (tpl_dir / "template.yaml").write_text(
            yaml.dump(template_data, default_flow_style=False)
        )
        clab_data = {
            "name": "test_tpl_base",
            "topology": {
                "nodes": {"attacker": {"kind": "linux", "image": "kali"}},
                "links": [],
            },
        }
        (tpl_dir / "clab.yaml").write_text(
            yaml.dump(clab_data, default_flow_style=False)
        )

        loader = TemplateLoader(templates_dir=str(tmp_path))
        tpl = loader.load("test_tpl")
        assert tpl.name == "test_tpl"
        assert len(tpl.injection_points) == 1
        assert tpl.injection_points[0].required_mitre == ["initial_access"]


# ── Multi-template tests ─────────────────────────────────

class TestAllTemplates:
    """验证所有模板都能正确加载"""

    @pytest.fixture
    def loader(self):
        return TemplateLoader(templates_dir="templates")

    def test_list_includes_all(self, loader):
        templates = loader.list_available()
        assert "dmz_simple" in templates
        assert "dmz_dual" in templates
        assert "enterprise_3tier" in templates

    def test_dmz_dual_structure(self, loader):
        tpl = loader.load("dmz_dual")
        assert tpl.name == "dmz_dual"
        assert len(tpl.injection_points) == 2
        assert tpl.injection_points[0].id == "dmz-target-1"
        assert tpl.injection_points[1].id == "dmz-target-2"
        # Both in same zone
        assert tpl.injection_points[0].zone == "dmz"
        assert tpl.injection_points[1].zone == "dmz"

    def test_dmz_dual_clab_base(self, loader):
        clab = loader.load_clab_base("dmz_dual")
        assert "attacker" in clab["topology"]["nodes"]
        assert "edge-router" in clab["topology"]["nodes"]

    def test_enterprise_3tier_structure(self, loader):
        tpl = loader.load("enterprise_3tier")
        assert tpl.name == "enterprise_3tier"
        assert len(tpl.zones) == 3
        assert "dmz" in tpl.zones
        assert "app" in tpl.zones
        assert "data" in tpl.zones
        assert len(tpl.routers) == 3
        assert len(tpl.injection_points) == 3

    def test_enterprise_3tier_noise_levels(self, loader):
        tpl = loader.load("enterprise_3tier")
        assert "none" in tpl.noise_levels
        assert "low" in tpl.noise_levels
        assert tpl.noise_levels["none"] == []
        low = tpl.noise_levels["low"]
        assert len(low) == 5
        zones = {s.zone for s in low}
        assert zones == {"dmz", "app", "data"}
        # each low-level service is a real NoiseService with parsed fields
        for s in low:
            assert s.name.startswith("decoy-")
            assert s.image
            assert isinstance(s.ports, list)
        # postgres decoy replaced by lightweight alpine+nc listener (no env)
        # busybox decoy carries a command
        bb = next(s for s in low if s.name == "decoy-data-05")
        assert bb.command == "httpd -f -p 8080"

    def test_enterprise_3tier_injection_zones(self, loader):
        tpl = loader.load("enterprise_3tier")
        zones = [ip.zone for ip in tpl.injection_points]
        assert zones == ["dmz", "app", "data"]

    def test_enterprise_3tier_isolation(self, loader):
        tpl = loader.load("enterprise_3tier")
        assert len(tpl.isolation_rules) >= 4
        # attacker → dmz accepted
        accept_dmz = any(
            r.from_zone == "attacker" and r.to_zone == "dmz" and r.action == "accept"
            for r in tpl.isolation_rules
        )
        assert accept_dmz

    def test_enterprise_3tier_clab_base(self, loader):
        clab = loader.load_clab_base("enterprise_3tier")
        nodes = clab["topology"]["nodes"]
        assert "attacker" in nodes
        assert "edge-router" in nodes
        assert "app-router" in nodes
        assert "data-router" in nodes
        # 3 links: attacker-edge, edge-app, app-data
        assert len(clab["topology"]["links"]) == 3

    def test_enterprise_3tier_ansible_base(self, loader):
        ansible = loader.load_ansible_base("enterprise_3tier")
        # Should configure all 3 routers
        assert "edge-router" in ansible
        assert "app-router" in ansible
        assert "data-router" in ansible

    def test_all_templates_have_clab_and_ansible(self, loader):
        """每个模板都有 clab.yaml 和 ansible/base.yaml"""
        for name in loader.list_available():
            clab = loader.load_clab_base(name)
            assert "topology" in clab, f"{name} missing topology in clab.yaml"
            ansible = loader.load_ansible_base(name)
            assert ansible, f"{name} has empty ansible/base.yaml"
