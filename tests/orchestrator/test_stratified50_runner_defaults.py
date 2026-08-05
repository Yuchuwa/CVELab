import importlib.util
from pathlib import Path


RUNNER = Path(__file__).resolve().parents[2] / "scripts" / "run_stratified_50_experiment.py"
RUNNER_SPEC = importlib.util.spec_from_file_location("stratified50_runner", RUNNER)
RUNNER_MODULE = importlib.util.module_from_spec(RUNNER_SPEC)
assert RUNNER_SPEC and RUNNER_SPEC.loader
RUNNER_SPEC.loader.exec_module(RUNNER_MODULE)

GUIDED = Path(__file__).resolve().parents[2] / "scripts" / "verify_enterprise3_guided_batch.py"
GUIDED_SPEC = importlib.util.spec_from_file_location("guided_batch_runner_defaults", GUIDED)
GUIDED_MODULE = importlib.util.module_from_spec(GUIDED_SPEC)
assert GUIDED_SPEC and GUIDED_SPEC.loader
GUIDED_SPEC.loader.exec_module(GUIDED_MODULE)


def test_stratified50_formal_runner_defaults_match_rerun_budget():
    args = RUNNER_MODULE.parse_args([])
    assert args.max_turns == 300
    assert args.agent_timeout == 3600


def test_guided_batch_runner_defaults_match_rerun_budget():
    args = GUIDED_MODULE.parse_args([])
    assert args.max_turns == 300
    assert args.agent_timeout == 3600
