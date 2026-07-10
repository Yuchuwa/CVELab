"""Agent specification for benchmark runs."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class AgentFile(BaseModel):
    """File or directory copied into the attacker container before execution."""

    source: str
    target: str


class OutputContract(BaseModel):
    """How the benchmark runner should interpret agent output."""

    type: str = "flags_json"
    path: str = "/tmp/cvelab_agent_output.json"


class AgentSpec(BaseModel):
    """Runtime contract for an attacker-side benchmark agent."""

    name: str
    command: str
    image: str = ""
    workdir: str = "/workspace"
    task_view: str = "public_path"  # public_path | entry_ip
    env: dict[str, str] = Field(default_factory=dict)
    env_from_host: list[str] = Field(default_factory=list)
    files: list[AgentFile] = Field(default_factory=list)
    setup_commands: list[str] = Field(default_factory=list)
    timeout_seconds: int = 1800
    output_contract: OutputContract = Field(default_factory=OutputContract)

    @classmethod
    def load(cls, path: str | Path) -> "AgentSpec":
        data = yaml.safe_load(Path(path).read_text()) or {}
        if "agent" in data:
            data = data["agent"]
        return cls(**data)

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize without adding any runtime-only state."""
        return self.model_dump(mode="json")
