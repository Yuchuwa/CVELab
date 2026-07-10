"""Benchmark runner for evaluating attacker-node agents."""

import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from clab_builder.orchestrator.benchmark.agent_spec import AgentSpec
from clab_builder.orchestrator.benchmark.runtime_validator import RuntimeValidator
from clab_builder.orchestrator.benchmark.scoring import score_agent_result


class BenchmarkRunner:
    """Deploy a scenario, run an agent inside attacker, score results, save artifacts."""

    def __init__(
        self,
        scenario_dir: str,
        agent_spec: AgentSpec,
        runs_dir: str = "runs",
        keep_running: bool = False,
        skip_deploy: bool = False,
        skip_runtime_validation: bool = False,
        atoms_dir: str = "data/atoms",
    ):
        self.scenario_path = Path(scenario_dir)
        self.agent_spec = agent_spec
        self.runs_dir = Path(runs_dir)
        self.keep_running = keep_running
        self.skip_deploy = skip_deploy
        self.skip_runtime_validation = skip_runtime_validation
        self.atoms_dir = atoms_dir

        self.clab = yaml.safe_load((self.scenario_path / "clab.yaml").read_text())
        self.ground_truth = json.loads((self.scenario_path / "ground_truth.json").read_text())
        self.scenario_meta = self._load_yaml(self.scenario_path / "scenario.yaml")
        self.lab_name = self.clab.get("name", self.scenario_path.name)
        self.run_dir = self._make_run_dir()

    def run(self) -> dict[str, Any]:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "agent_spec.yaml").write_text(
            yaml.dump({"agent": self.agent_spec.to_public_dict()}, sort_keys=False)
        )

        deployed = False
        try:
            if not self.skip_deploy:
                self._deploy()
                deployed = True
                self._run_ansible("base.yaml")
                self._run_ansible("cve-setup.yaml")

            runtime_validation = {"success": True, "checks": []}
            if not self.skip_runtime_validation:
                runtime_validation = RuntimeValidator(
                    str(self.scenario_path),
                    atoms_dir=self.atoms_dir,
                ).validate()
                (self.run_dir / "runtime_validation.json").write_text(
                    json.dumps(runtime_validation, indent=2, ensure_ascii=False)
                )
                if not runtime_validation["success"]:
                    result = self._final_result(
                        success=False,
                        runtime_validation=runtime_validation,
                        agent_result={},
                        score={},
                        error="Runtime validation failed",
                    )
                    self._write_result(result)
                    return result

            agent_result = self._run_agent()
            score = score_agent_result(agent_result, self.ground_truth)
            result = self._final_result(
                success=score["all_captured"],
                runtime_validation=runtime_validation,
                agent_result=agent_result,
                score=score,
            )
            self._write_result(result)
            return result
        finally:
            if deployed and not self.keep_running:
                self._destroy()

    def _run_agent(self) -> dict[str, Any]:
        attacker = self._container_name("attacker")
        self._prepare_agent_workspace(attacker)
        self._write_task_input(attacker)

        for setup in self.agent_spec.setup_commands:
            self._docker_exec(attacker, setup, timeout=300, check=True)

        stdout_path = self.run_dir / "agent_stdout.log"
        stderr_path = self.run_dir / "agent_stderr.log"
        command = self.agent_spec.command
        exec_cmd = ["docker", "exec", "-w", self.agent_spec.workdir]
        for key, value in self._agent_env().items():
            exec_cmd.extend(["-e", f"{key}={value}"])
        exec_cmd.extend([attacker, "sh", "-lc", command])

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        proc = subprocess.Popen(
            exec_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        def read_stream(stream, chunks: list[str], log_path: Path, echo):
            with log_path.open("w") as log:
                for line in stream:
                    chunks.append(line)
                    log.write(line)
                    log.flush()
                    echo(line, end="", flush=True)

        stdout_thread = threading.Thread(
            target=read_stream,
            args=(proc.stdout, stdout_chunks, stdout_path, print),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=read_stream,
            args=(proc.stderr, stderr_chunks, stderr_path, lambda *a, **k: print(*a, file=sys.stderr, **k)),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        try:
            proc.wait(timeout=self.agent_spec.timeout_seconds)
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            with stderr_path.open("a") as stderr_log:
                stderr_log.write("\nAgent timed out\n")
            self._collect_agent_artifacts(attacker)
            return {
                "success": False,
                "verified_flags": {},
                "error": f"timeout after {self.agent_spec.timeout_seconds}s",
            }

        output_contract = self.agent_spec.output_contract
        agent_output_path = self.run_dir / "agent_output.json"
        copied = self._copy_from_container(
            attacker,
            output_contract.path,
            agent_output_path,
        )
        if copied:
            try:
                data = json.loads(agent_output_path.read_text())
                data.setdefault("exit_code", proc.returncode)
                self._collect_agent_artifacts(attacker)
                return data
            except json.JSONDecodeError:
                pass

        extracted = self._extract_json("".join(stdout_chunks))
        if extracted:
            extracted.setdefault("exit_code", proc.returncode)
            agent_output_path.write_text(json.dumps(extracted, indent=2, ensure_ascii=False))
            self._collect_agent_artifacts(attacker)
            return extracted

        self._collect_agent_artifacts(attacker)
        return {
            "success": proc.returncode == 0,
            "verified_flags": {},
            "exit_code": proc.returncode,
            "error": "agent output contract was not satisfied",
        }

    def _prepare_agent_workspace(self, attacker: str):
        self._docker_exec(attacker, f"mkdir -p {self.agent_spec.workdir}", timeout=30, check=True)
        for mapping in self.agent_spec.files:
            source = Path(mapping.source)
            if not source.exists():
                raise FileNotFoundError(f"Agent file source not found: {source}")
            self._run([
                "docker", "cp", str(source.resolve()), f"{attacker}:{mapping.target}"
            ], timeout=120, check=True)

    def _write_task_input(self, attacker: str):
        task = self._task_input()
        task_path = self.run_dir / "task.json"
        task_path.write_text(json.dumps(task, indent=2, ensure_ascii=False))
        self._run([
            "docker", "cp", str(task_path.resolve()), f"{attacker}:{self.agent_spec.workdir}/task.json"
        ], timeout=30, check=True)

    def _task_input(self) -> dict[str, Any]:
        if self.agent_spec.task_view == "entry_ip":
            return {"ip": self._entry_ip()}
        if self.agent_spec.task_view != "public_path":
            raise ValueError(f"Unsupported agent task_view: {self.agent_spec.task_view}")
        return {
            "scenario_name": self.ground_truth.get("scenario", self.lab_name),
            "attack_path": self._public_attack_path(),
            "ip_allocations": self.scenario_meta.get("ip_allocations", {}),
            "output_contract": self.agent_spec.output_contract.model_dump(mode="json"),
        }

    def _entry_ip(self) -> str:
        attack_path = self.ground_truth.get("attack_path", [])
        if not attack_path:
            return ""
        return attack_path[0].get("target_ip", "")

    def _public_attack_path(self) -> list[dict[str, Any]]:
        public_steps = []
        hidden = {"flag"}
        for step in self.ground_truth.get("attack_path", []):
            public_step = {
                key: value
                for key, value in step.items()
                if key not in hidden
            }
            public_step.setdefault("ports", self._atom_ports(public_step.get("cve_id", "")))
            public_steps.append(public_step)
        return public_steps

    def _atom_ports(self, cve_id: str) -> list[int]:
        atom_yaml = Path(self.atoms_dir) / cve_id / "atom.yaml"
        if not atom_yaml.exists():
            return []
        data = yaml.safe_load(atom_yaml.read_text()) or {}
        ports = data.get("ports", [])
        return [int(port) for port in ports if isinstance(port, int | str) and str(port).isdigit()]

    def _agent_env(self) -> dict[str, str]:
        env = dict(self.agent_spec.env)
        for name in self.agent_spec.env_from_host:
            if name in os.environ:
                env[name] = os.environ[name]
        if "ANTHROPIC_API_KEY" not in env and os.environ.get("LLM_API_KEY"):
            env["ANTHROPIC_API_KEY"] = os.environ["LLM_API_KEY"]
        if "ANTHROPIC_BASE_URL" not in env and os.environ.get("LLM_BASE_URL"):
            env["ANTHROPIC_BASE_URL"] = os.environ["LLM_BASE_URL"]
        if "MODEL" not in env and os.environ.get("LLM_MODEL"):
            env["MODEL"] = os.environ["LLM_MODEL"]
        env.setdefault("CVELAB_TASK", f"{self.agent_spec.workdir}/task.json")
        env.setdefault("CVELAB_OUTPUT", self.agent_spec.output_contract.path)
        env.setdefault("CVELAB_SCENARIO", self.ground_truth.get("scenario", self.lab_name))
        return env

    def _deploy(self):
        self._run([
            "clab", "deploy", "-t", str((self.scenario_path / "clab.yaml").resolve())
        ], timeout=300, check=True)

    def _destroy(self):
        self._run([
            "clab", "destroy", "-t", str((self.scenario_path / "clab.yaml").resolve()), "--cleanup"
        ], timeout=180, check=False)

    def _run_ansible(self, playbook: str):
        pb_path = self.scenario_path / "ansible" / playbook
        if not pb_path.exists():
            return
        inventory = self.scenario_path / f"clab-{self.lab_name}" / "inventory" / "hosts.yaml"
        cmd = ["ansible-playbook", str(pb_path.resolve())]
        if inventory.exists():
            cmd.extend(["-i", str(inventory.resolve())])
        self._run(cmd, cwd=self.scenario_path, timeout=300, check=False)

    def _docker_exec(self, container: str, command: str, timeout: int, check: bool):
        self._run(["docker", "exec", container, "sh", "-lc", command], timeout=timeout, check=check)

    def _copy_from_container(self, container: str, src: str, dst: Path) -> bool:
        result = self._run(["docker", "cp", f"{container}:{src}", str(dst)], timeout=30, check=False)
        return result.returncode == 0 and dst.exists()

    def _collect_agent_artifacts(self, container: str):
        output_path = self.agent_spec.output_contract.path
        session_path = output_path.replace("output.json", "session.json")
        if session_path != output_path:
            self._copy_from_container(container, session_path, self.run_dir / "agent_session.json")
        env = self._agent_env()
        claude_config_dir = env.get("CLAUDE_CONFIG_DIR") or f"{self.agent_spec.workdir}/.claude"
        self._copy_from_container(
            container,
            f"{claude_config_dir.rstrip('/')}/projects",
            self.run_dir / "agent_claude_projects",
        )
        self._copy_from_container(
            container,
            "/tmp/claude-1000",
            self.run_dir / "agent_tmp_claude",
        )

    def _run(
        self,
        cmd: list[str],
        timeout: int,
        check: bool,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd.resolve()) if cwd else None,
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
                f"stdout={result.stdout[-1000:]}\nstderr={result.stderr[-1000:]}"
            )
        return result

    def _container_name(self, node: str) -> str:
        return f"clab-{self.lab_name}-{node}"

    def _make_run_dir(self) -> Path:
        scenario = self.ground_truth.get("scenario", self.lab_name)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return self.runs_dir / f"{self._slug(scenario)}__{self._slug(self.agent_spec.name)}__{stamp}"

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text()) or {}

    def _final_result(
        self,
        success: bool,
        runtime_validation: dict[str, Any],
        agent_result: dict[str, Any],
        score: dict[str, Any],
        error: str = "",
    ) -> dict[str, Any]:
        return {
            "success": success,
            "error": error,
            "scenario": self.ground_truth.get("scenario", self.lab_name),
            "agent": self.agent_spec.name,
            "run_dir": str(self.run_dir),
            "runtime_validation": runtime_validation,
            "agent_result": agent_result,
            "score": score,
        }

    def _write_result(self, result: dict[str, Any]):
        (self.run_dir / "benchmark_result.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False)
        )

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        match = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", text)
        if match:
            text = match.group(1)
        else:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                return None
            text = text[start:end + 1]
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def _slug(self, value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-").lower() or "run"
