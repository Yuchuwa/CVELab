import json
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VARIANT = ROOT / "data/experiments/stratified-50/sysarmor-case0"


def load_materializer():
    path = VARIANT / "scripts/materialize-defended-scenario.py"
    spec = importlib.util.spec_from_file_location("sysarmor_case0_materializer", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_materializer_preserves_original_images_and_commands():
    materializer = load_materializer()
    nodes = {
        target: {"kind": "linux", "image": f"original-{target}", "cmd": f"run-{target}"}
        for target in ("target-1", "target-2", "target-3")
    }

    patched = materializer.patch_clab({"topology": {"nodes": nodes}})

    for target, node in patched["topology"]["nodes"].items():
        assert node["image"] == f"original-{target}"
        assert node["cmd"] == f"run-{target}"
        assert node["restart-policy"] == "unless-stopped"
        assert "/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro" in node["binds"]
        assert "/sys/fs/bpf:/sys/fs/bpf" in node["binds"]
        assert "privileged" not in node
        assert "docker-opts" not in node


def test_case0_sysarmor_scripts_exist_and_are_executable():
    for rel in [
        "scripts/prepare-assets.sh",
        "scripts/inject-runtime.sh",
        "scripts/deploy-and-inject.sh",
        "scripts/materialize-defended-scenario.py",
        "scripts/smoke-target1.sh",
    ]:
        path = VARIANT / rel
        assert path.exists()
        assert path.stat().st_mode & 0o111


def test_case0_pins_sysarmor_rc5_release_asset():
    manifest = (VARIANT / "scripts/runtime-assets.env").read_text()
    assert 'SYSARMOR_RELEASE_TAG="v0.1.0-rc.5"' in manifest
    assert (
        'SYSARMOR_PACKAGE_FILE="sysarmor-agent-linux-amd64-v0.1.0-rc.5.tar.gz"'
        in manifest
    )
    assert (
        'SYSARMOR_PACKAGE_URL="https://github.com/PKU-ASAL/sysarmor/releases/download/'
        'v0.1.0-rc.5/sysarmor-agent-linux-amd64-v0.1.0-rc.5.tar.gz"'
        in manifest
    )
    assert (
        'SYSARMOR_PACKAGE_SHA256="e2ea105552b1e37ab8badb2f03da0f622309bdabaa1010a257cf19c2cca7eb26"'
        in manifest
    )
    assert (
        'JQ_SHA256="5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5"'
        in manifest
    )


def test_materializer_declares_sysarmor_runtime_requirements():
    text = (VARIANT / "scripts/materialize-defended-scenario.py").read_text()
    for needle in [
        "/sys/fs/bpf:/sys/fs/bpf",
        "/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro",
    ]:
        assert needle in text


def test_deploy_workflow_gates_on_all_targets_and_readme_uses_original_images():
    workflow = (VARIANT / "scripts/deploy-and-inject.sh").read_text()
    assert workflow.index("prepare-assets.sh") < workflow.index("clab deploy")
    assert workflow.index("clab deploy") < workflow.index("inject-runtime.sh")
    for target in ("target-1", "target-2", "target-3"):
        assert f"--target {target}" in workflow

    readme = (VARIANT / "README.md").read_text()
    assert "scripts/deploy-and-inject.sh" in readme
    assert "scripts/build-images.sh" not in readme
    assert "sysarmor-case0-target-1:latest" not in readme


def test_target1_smoke_mounts_original_atom_runtime_content():
    smoke = (VARIANT / "scripts/smoke-target1.sh").read_text()
    assert "data/atoms/CVE-2018-16509/init/index.php:/var/www/html/index.php:ro" in smoke
    assert "pgrep -xc sysarmor-agent" in smoke


def test_injector_runs_sysarmor_operations_as_root_without_changing_workload_user():
    script = (VARIANT / "scripts/inject-runtime.sh").read_text()
    assert "docker exec -u 0" in script
    assert "docker update" not in script
    assert "docker commit" not in script


def test_general_behavior_rules_are_additive_and_product_agnostic():
    rules = VARIANT / "rules"
    rulepack = json.loads((rules / "rulepack-general-behavior.json").read_text())
    policy = json.loads((rules / "detection-policy.json").read_text())

    assert policy["policy_id"] == "cvelab-general-behavior"
    assert policy["mode"] == "observe"
    assert {ruleset["ref"] for ruleset in policy["rulesets"]} == {
        "ruleset:cep-endpoint",
        "ruleset:cvelab-general-behavior",
    }
    assert all(ruleset["enabled"] is True for ruleset in policy["rulesets"])

    assert rulepack["metadata"] == {
        "id": "rulepack:cvelab-general-behavior",
        "version": "v1",
    }
    rulesets = rulepack["spec"]["rulesets"]
    assert len(rulesets) == 1
    assert rulesets[0]["id"] == "ruleset:cvelab-general-behavior"
    assert rulesets[0]["version"] == "v1"
    assert {rule["rule_id"] for rule in rulesets[0]["rules"]} == {
        "workload_executes_shell_or_interpreter",
        "execution_tool_opens_network_connection",
        "network_client_used_in_workload",
    }
    assert {rule["runtime"]["type"] for rule in rulesets[0]["rules"]} == {
        "expr",
        "sequence",
    }
    assert all("suppress" in rule for rule in rulesets[0]["rules"])

    raw = "\n".join(path.read_text().lower() for path in rules.glob("*.json"))
    for forbidden in (
        "elasticsearch",
        "grafana",
        "apache",
        "postgresql",
        "cve-",
        "/flag",
        "/opt/cvelab",
    ):
        assert forbidden not in raw
