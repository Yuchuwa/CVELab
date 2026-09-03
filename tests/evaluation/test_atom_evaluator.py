from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from clab_builder.evaluation.atom_evaluator import evaluate_atom


@pytest.mark.parametrize(
    ("captured_flag", "expected_success"),
    [("flag{expected}", True), ("flag{fabricated}", False)],
)
def test_atom_evaluator_uses_private_flag_oracle(
    tmp_path, captured_flag, expected_success
):
    atom_dir = tmp_path / "CVE-TEST"
    atom_dir.mkdir()
    (atom_dir / "atom.yaml").write_text(
        "\n".join([
            "cve_id: CVE-TEST",
            "description: test",
            "flag_value: flag{expected}",
            "runtime_spec:",
            "  ports: [8080]",
        ])
    )
    inspect = SimpleNamespace(
        returncode=0,
        stdout='{"test-network": {}}',
        stderr="",
    )
    output = SimpleNamespace(
        success=True,
        captured_flag=captured_flag,
    )
    agent = MagicMock()
    agent.run.return_value = output

    with (
        patch(
            "clab_builder.evaluation.atom_evaluator.subprocess.run",
            return_value=inspect,
        ),
        patch(
            "clab_builder.evaluation.atom_evaluator.SecurityResearcherAgent",
            return_value=agent,
        ),
    ):
        runs, environment_valid, _ = evaluate_atom(
            str(atom_dir),
            container="target",
            target_ip="10.0.0.2",
            models=("model-a",),
            api_key="test",
            base_url="",
            max_turns=30,
            timeout=1800,
        )

    assert environment_valid is True
    assert runs[0].success is expected_success
    assert runs[0].verifier["agent_reported_success"] is True
    assert runs[0].verifier["flag_matched"] is expected_success
