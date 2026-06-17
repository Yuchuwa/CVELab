"""Scenario Verifier — 单命令完成：deploy → ansible → agent → verify → destroy → save

生命周期:
  1. clab deploy -t <scenario>/clab.yaml
  2. ansible-playbook base.yaml  (IP 配置 + 路由 + 管理网络禁用)
  3. ansible-playbook cve-setup.yaml (等待服务就绪)
  4. 在 attacker 容器内运行 scenario_runner.py
  5. 收集结果 → 与 ground_truth 比对
  6. clab destroy
  7. 保存 verify_result.json + session.json
"""

import json
import subprocess
from pathlib import Path

from clab_builder.orchestrator.composer.scenario_runner import (
    DEFAULT_MAX_TURNS as DEFAULT_AGENT_TURNS,
)

SCENARIO_RUNNER_SRC = Path(__file__).parent / "scenario_runner.py"


class ScenarioVerifier:
    """场景验证器：一条命令完成全流程"""

    def __init__(self, max_turns: int = DEFAULT_AGENT_TURNS):
        self.max_turns = max_turns
        self.agent_image = "clab-agent:latest"

    def run_full(
        self,
        scenario_dir: str,
        api_key: str,
        base_url: str = "",
        model: str = "",
    ) -> dict:
        """单命令完整流程：deploy → ansible → agent → verify → destroy → save

        Returns:
            完整验证结果
        """
        scenario_path = Path(scenario_dir)

        # 读取 ground_truth 和 ip_allocations
        gt_file = scenario_path / "ground_truth.json"
        if not gt_file.exists():
            raise FileNotFoundError(f"ground_truth.json not found in {scenario_dir}")
        ground_truth = json.loads(gt_file.read_text())

        ip_alloc = {}
        scenario_meta = scenario_path / "scenario.yaml"
        if scenario_meta.exists():
            import yaml
            meta = yaml.safe_load(scenario_meta.read_text())
            ip_alloc = meta.get("ip_allocations", {})

        try:
            # 1. Deploy
            print("[1/5] Deploying...")
            if not self._deploy(scenario_dir):
                return self._save_result(scenario_path, {
                    "success": False, "error": "Deploy failed",
                }, ground_truth)

            # 2. Ansible base (IP config + routing)
            print("[2/5] Configuring network (ansible base)...")
            self._run_ansible(scenario_dir, "base.yaml")

            # 3. Ansible cve-setup (wait for services)
            print("[3/5] Waiting for services (ansible cve-setup)...")
            self._run_ansible(scenario_dir, "cve-setup.yaml")

            # 4. Run agent
            print("[4/5] Running agent verification...")
            agent_result = self._run_agent(
                scenario_dir, ground_truth, ip_alloc,
                api_key=api_key, base_url=base_url, model=model,
            )

            # 5. Verify flags + save
            print("[5/5] Verifying results...")
            flag_result = self._verify_flags(agent_result, ground_truth)
            result = self._save_result(scenario_path, {
                "agent_result": agent_result,
                "flag_verification": flag_result,
                "success": flag_result["all_captured"],
            }, ground_truth)

            return result

        finally:
            # Always destroy
            print("[Cleanup] Destroying...")
            self._destroy(scenario_dir)

    # ── 内部步骤 ──────────────────────────────────────

    def _deploy(self, scenario_dir: str, timeout: int = 300) -> bool:
        """clab deploy"""
        scenario_path = Path(scenario_dir)
        clab_file = scenario_path / "clab.yaml"

        if not clab_file.exists():
            raise FileNotFoundError(f"clab.yaml not found in {scenario_dir}")

        result = subprocess.run(
            ["clab", "deploy", "-t", str(clab_file)],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            print(f"  Deploy failed: {result.stderr}")
            return False
        print("  Deployed OK")
        return True

    def _run_ansible(self, scenario_dir: str, playbook: str, timeout: int = 300):
        """运行 ansible playbook"""
        scenario_path = Path(scenario_dir)
        import yaml

        with open(scenario_path / "clab.yaml") as f:
            lab_name = yaml.safe_load(f).get("name", "")

        pb_path = scenario_path / "ansible" / playbook
        if not pb_path.exists():
            return

        # CLab generates inventory in the topology directory
        inventory = scenario_path / f"clab-{lab_name}" / "inventory" / "hosts.yaml"
        if not inventory.exists():
            # Fallback: auto-generated inventory name
            inventory = scenario_path / f"{lab_name}-inventory.yaml"

        cmd = ["ansible-playbook", str(pb_path.resolve())]
        if inventory.exists():
            cmd.extend(["-i", str(inventory.resolve())])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(scenario_path.resolve()),
        )
        if result.returncode != 0:
            print(f"  Ansible {playbook} warning: {result.stderr[:300]}")
        else:
            print(f"  Ansible {playbook} OK")

    def _run_agent(
        self,
        scenario_dir: str,
        ground_truth: dict,
        ip_alloc: dict,
        api_key: str,
        base_url: str = "",
        model: str = "",
    ) -> dict:
        """在 attacker 容器内运行 scenario_runner.py"""
        import threading

        scenario_path = Path(scenario_dir)
        import yaml

        with open(scenario_path / "clab.yaml") as f:
            clab_data = yaml.safe_load(f)
        lab_name = clab_data.get("name", "")

        # attacker 容器名
        attacker_container = f"clab-{lab_name}-attacker"
        attacker_ip = ip_alloc.get("attacker", {}).get("eth1", "").split("/")[0]

        # 构建 agent input（用数据面 IP）
        targets = []
        for step in ground_truth.get("attack_path", []):
            node_name = step["target_node"]
            cve_id = step["cve_id"]

            playbook_text = self._load_atom_playbook(cve_id)
            flag_cmd = self._load_atom_flag_command(cve_id)
            atom_config = self._load_atom_config(cve_id)
            internal_ports = atom_config.ports if atom_config else []
            flag_hint = step.get("flag_hint", "file:/flag.txt")

            # 数据面 IP（从 ip_allocations）
            node_ip = ip_alloc.get(node_name, {}).get("eth1", "").split("/")[0]
            if not node_ip:
                node_ip = step.get("target_ip", node_name)

            targets.append({
                "node_name": node_name,
                "cve_id": cve_id,
                "ip": node_ip,
                "ports": internal_ports,
                "zone": step.get("zone", ""),
                "flag_hint": flag_hint,
                "flag_verify_command": flag_cmd,
                "playbook": playbook_text,
            })

        input_data = {
            "scenario_name": ground_truth.get("scenario", lab_name),
            "attacker_ip": attacker_ip,
            "targets": targets,
            "ground_truth": ground_truth,
        }

        # 准备 workspace
        workspace = scenario_path / "agent_workspace"
        workspace.mkdir(exist_ok=True)
        input_path = workspace / "input.json"
        output_path = workspace / "output.json"
        input_path.write_text(json.dumps(input_data, indent=2, ensure_ascii=False))
        if output_path.exists():
            output_path.unlink()

        # 拷入 runner + input
        subprocess.run(
            ["docker", "cp", str(SCENARIO_RUNNER_SRC.resolve()),
             f"{attacker_container}:/opt/scenario_runner.py"],
            capture_output=True, timeout=30,
        )
        subprocess.run(
            ["docker", "cp", str(input_path),
             f"{attacker_container}:/tmp/scenario_input.json"],
            capture_output=True, timeout=30,
        )

        # 构建 docker exec 命令
        full_cmd = ["docker", "exec"]
        env_flags = [f"ANTHROPIC_API_KEY={api_key}"]
        if base_url:
            env_flags.append(f"ANTHROPIC_BASE_URL={base_url}")
        if model:
            env_flags.append(f"MODEL={model}")
        for ef in env_flags:
            full_cmd.extend(["-e", ef])
        full_cmd.extend([
            attacker_container,
            "python3", "/opt/scenario_runner.py",
            "--input", "/tmp/scenario_input.json",
            "--output", "/tmp/scenario_output.json",
            "--max-turns", str(self.max_turns),
        ])

        # 执行
        stderr_chunks = []
        try:
            proc = subprocess.Popen(
                full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            def read_stderr():
                for line in proc.stderr:
                    stderr_chunks.append(line)
                    print(line, end="", flush=True)
            reader = threading.Thread(target=read_stderr, daemon=True)
            reader.start()
            proc.wait(timeout=1800)
            reader.join(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stderr_chunks.append("Agent timed out after 30 minutes")

        # 拷出 output + session
        subprocess.run(
            ["docker", "cp",
             f"{attacker_container}:/tmp/scenario_output.json",
             str(output_path)],
            capture_output=True, timeout=30,
        )
        session_path = workspace / "session.json"
        subprocess.run(
            ["docker", "cp",
             f"{attacker_container}:/tmp/scenario_session.json",
             str(session_path)],
            capture_output=True, timeout=30,
        )
        if session_path.exists():
            print(f"  Session saved: {session_path}")

        if output_path.exists():
            try:
                return json.loads(output_path.read_text())
            except json.JSONDecodeError:
                pass

        return {
            "scenario_name": ground_truth.get("scenario", ""),
            "success": False,
            "verified_flags": {},
            "attack_log": [],
            "evidence": [f"Agent failed: {''.join(stderr_chunks)[:500]}"],
            "failed_targets": [t["node_name"] for t in targets],
        }

    def _verify_flags(self, agent_result: dict, ground_truth: dict) -> dict:
        """比对 agent 结果与 ground truth"""
        captured = agent_result.get("verified_flags", {})
        expected = {}
        for step in ground_truth.get("attack_path", []):
            expected[step["target_node"]] = step["flag"]

        per_target = {}
        for node, exp_flag in expected.items():
            cap_flag = captured.get(node, "")
            per_target[node] = {
                "expected": exp_flag,
                "captured": cap_flag,
                "match": cap_flag == exp_flag,
            }

        return {
            "all_captured": all(v["match"] for v in per_target.values()),
            "per_target": per_target,
        }

    def verify_flags(self, agent_result: dict, ground_truth: dict) -> dict:
        """Public wrapper for flag verification."""
        return self._verify_flags(agent_result, ground_truth)

    def _get_node_ports(self, clab_data: dict, node_name: str) -> list[int]:
        """Extract configured ports from a clab node definition."""
        node = clab_data.get("topology", {}).get("nodes", {}).get(node_name, {})
        return node.get("ports", [])

    def _save_result(self, scenario_path: Path, result: dict, ground_truth: dict) -> dict:
        """保存验证结果到场景目录"""
        result_file = scenario_path / "verify_result.json"
        result_file.write_text(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"  Result saved: {result_file}")

        # 打印摘要
        if "flag_verification" in result:
            fv = result["flag_verification"]
            status = "PASS" if fv["all_captured"] else "FAIL"
            print(f"\n  Result: {status}")
            for node, info in fv["per_target"].items():
                s = "CAPTURED" if info["match"] else "MISSED"
                print(f"    {node}: {s}")

        return result

    def _destroy(self, scenario_dir: str):
        """clab destroy"""
        clab_file = Path(scenario_dir) / "clab.yaml"
        if not clab_file.exists():
            return

        result = subprocess.run(
            ["clab", "destroy", "-t", str(clab_file), "--cleanup"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  Destroy warning: {result.stderr[:200]}")
        else:
            print("  Destroyed OK")

    # ── Atom 数据加载 ──────────────────────────────────

    def _load_atom_playbook(self, cve_id: str) -> str:
        playbook_dir = Path("data/atoms") / cve_id / "playbook"
        if not playbook_dir.exists():
            return ""
        parts = []
        for f in sorted(playbook_dir.iterdir()):
            if f.is_file() and f.suffix in (".yaml", ".yml", ".sh"):
                parts.append(f"### {f.name}\n{f.read_text()}")
        return "\n\n".join(parts)

    def _load_atom_flag_command(self, cve_id: str) -> str:
        atom_yaml = Path("data/atoms") / cve_id / "atom.yaml"
        if not atom_yaml.exists():
            return ""
        import yaml
        data = yaml.safe_load(atom_yaml.read_text())
        return data.get("flag_verify_command", "")

    def _load_atom_config(self, cve_id: str):
        atom_yaml = Path("data/atoms") / cve_id / "atom.yaml"
        if not atom_yaml.exists():
            return None
        from clab_builder.shared.models.atom import AtomConfig
        import yaml
        data = yaml.safe_load(atom_yaml.read_text())
        try:
            return AtomConfig(**data)
        except Exception:
            return None
