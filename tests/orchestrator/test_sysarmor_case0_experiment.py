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
