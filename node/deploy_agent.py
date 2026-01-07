## 没有使用这个文件，请忽略

import json
from langchain.agents import create_agent
from langchain.chat_models import init_chat_model

from state import GraphState
from tools.containerlab_tools import clab_lifecycle_tool, ClabAction
from config import LLM_MODEL, BASE_URL, API_KEY


deploy_prompt = """
You are a Containerlab Deployment Specialist.

Your task is to deploy a network topology using Containerlab.

DEPLOYMENT PROCESS:
1. First, DESTROY any existing lab with cleanup to ensure a clean state
2. Then, DEPLOY the topology with reconfigure flag
3. Finally, INSPECT the deployed topology to get the container details

SUCCESS CRITERIA:
- Deploy command completes successfully (exit code 0)
- All containers are running
- Inspect returns valid JSON with container information

ERROR HANDLING:
- If deploy fails, capture the error logs
- Common issues: image pull failures, port conflicts, invalid YAML syntax
- Return detailed error information for troubleshooting

Available actions:
- destroy: Clean up existing deployment
- deploy/reconfigure: Deploy the topology
- inspect: Get deployment details in JSON format
"""

def deploy(state: GraphState):
    """
    Deploy the containerlab topology.

    If deployment fails:
        - Update state['deploy_logs'] with error logs

    If deployment succeeds:
        - Update state['deploy_logs'] with success logs
        - Proceed to configure node
    """
    file_path = state.get("yaml_path", None)
    if not file_path:
        error_msg = f"No YAML file path found in state"
        print(f"❌ {error_msg}")
        return {
            "is_deployed": False, 
            "error_logs": error_msg
        }

    print(f"\n🚀 [Stage 1] Deploying infrastructure from: {file_path}")

    # Initialize the model and agent
    model = init_chat_model(
        model_provider="openai",
        model=LLM_MODEL,
        temperature=0.1,
        base_url=BASE_URL,
        api_key=API_KEY
    )

    agent = create_agent(
        model=model,
        system_prompt=deploy_prompt,
        tools=[clab_lifecycle_tool]
    )

    # Construct the deployment task for the agent
    deploy_task = f"""
    Please deploy the topology located at: {file_path}

    Follow these steps:
    1. Run 'destroy' action with cleanup to remove any existing deployment
    2. Run 'reconfigure' action to deploy the topology
    3. Run 'inspect' action to get the deployment details

    After completing all steps, report the results.
    """

    try:
        print("🤖 Agent executing deployment sequence...")

        # Invoke the agent
        result = agent.invoke({
            "messages": [
                {"role": "user", "content": deploy_task}
            ]
        })

        # Extract the agent's response from messages
        messages = result.get("messages", [])
        if messages:
            last_msg = messages[-1]
            # AIMessage has a content attribute
            agent_response = last_msg.content if hasattr(last_msg, "content") else str(last_msg)
        else:
            agent_response = ""

        # Parse the deployment result
        # Check if deployment was successful by looking for success indicators
        deploy_success = _check_deploy_success(agent_response)

        if deploy_success:
            # Try to extract inspect data
            inspect_data = _extract_inspect_data(agent_response)

            print("✅ Infrastructure is UP. Handing over to Configure stage.")
            return {
                "error_logs": "",
                "is_deployed": True, 
                "inspect_data": inspect_data
            }
        else:
            print("❌ Deployment Failed. Returning to Generate stage.")
            return {
                "is_deployed": False, 
                "error_logs": agent_response,
            }

    except Exception as e:
        error_msg = f"Deployment exception: {str(e)}"
        print(f"❌ {error_msg}")
        return {
            "is_deployed": False, 
            "error_logs": error_msg
        }


def _check_deploy_success(response: str) -> bool:
    """Check if the deployment response indicates success."""
    success_indicators = [
        "deploy completed successfully",
        "deployment successful",
        "containers are running",
        "all nodes are up",
        "+---+"  # Containerlab table format
    ]

    response_lower = response.lower()
    for indicator in success_indicators:
        if indicator in response_lower:
            return True

    # Check for absence of error patterns
    error_patterns = [
        "failed (exit code",
        "error:",
        "command failed",
        "deployment failed"
    ]

    for pattern in error_patterns:
        if pattern in response_lower:
            return False

    # If inspect returned JSON data, consider it successful
    if "{" in response and "containers" in response.lower():
        return True

    return False


def _extract_inspect_data(response: str) -> dict:
    """
    Extract JSON inspect data from the agent response.

    Containerlab inspect returns format like:
    {
      "lab_name": [
        {
          "name": "clab-lab-node1",
          "container_id": "...",
          "image": "...",
          "state": "running",
          ...
        }
      ]
    }
    """
    try:
        import re

        # Try to find JSON content - look for the outermost object
        json_pattern = r'\{(?:[^{}]|(?:\{[^{}]*\}))*\}'
        matches = re.findall(json_pattern, response, re.DOTALL)

        for match in matches:
            try:
                data = json.loads(match)
                # Containerlab inspect output has lab_name as key with list value
                # The value is a list of container info dicts
                for key, value in data.items():
                    if isinstance(value, list) and len(value) > 0:
                        # Check if first item has container fields
                        item = value[0]
                        if isinstance(item, dict) and any(
                            k in item for k in ["name", "container_id", "image", "state", "kind"]
                        ):
                            return data
            except json.JSONDecodeError:
                continue

        return {}

    except Exception:
        return {}



