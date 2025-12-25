from state import GraphState
from langgraph.graph import StateGraph, START, END
from node.generate import generate
from node.deploy import deploy
from node.configure import configure
from node.builder import builder_node
from node.validate import validator_node
from node.fixer import fixer


def create_workflow():
    """Create and compile the LangGraph workflow."""
    workflow = StateGraph(GraphState)
    workflow.add_node("generator", generate)
    workflow.add_node("builder", builder_node)
    workflow.add_node("validator", validator_node)
    workflow.add_node("deployer", deploy)
    workflow.add_node("configurator", configure)
    workflow.add_node("fixer", fixer)

    workflow.add_edge(START, "generator")
    workflow.add_edge("generator","builder")

    def check_build_errors(state):
        return "validator" if not state.get("error_logs") else "fixer"

    def check_validation_errors(state):
        return "deployer" if not state.get("error_logs") else "fixer"
    
    def check_deploy_errors(state):
        # 逻辑：如果 is_deployed 为 False，或者 error_logs 不为空 -> 去 Fixer
        if not state.get("is_deployed", False) or state.get("error_logs"):
            print(f"❌ Deploy failed (Status check). Routing to Fixer...")
            return "fixer"        
        print("✅ Deploy success. Routing to Configure.")
        return "configurator"


    workflow.add_conditional_edges("builder", check_build_errors)
    workflow.add_conditional_edges("validator", check_validation_errors)
    workflow.add_conditional_edges("deployer", check_deploy_errors,{"configurator":"configurator","fixer":"fixer"})

    workflow.add_edge("fixer", "builder")  # Fixer always goes back to build
    workflow.add_edge("configurator", END)

    return workflow.compile()


def run(user_request: str):
    """Run the workflow with a user request."""
    print("=" * 60)
    print("🚀 ContainerLab Builder")
    print("=" * 60)

    app = create_workflow()

    initial_state: GraphState = {
        "user_request": user_request,
        "blueprint": None,
        "yaml_path": "",
        "error_logs": "",
        "is_deployed": False,
        "inspect_data": {},
        "retry_count": 0,
        "is_complete": False,
    }

    result = app.invoke(initial_state)

    print("\n" + "=" * 60)
    if result.get("is_complete"):
        print("✅ Workflow completed successfully!")
        if result.get("yaml_path"):
            print(f"📄 YAML file: {result['yaml_path']}")
    else:
        print("❌ Workflow did not complete as expected.")
        if result.get("error_logs"):
            print(f"Error: {result['error_logs']}")
    print("=" * 60)

    return result


if __name__ == "__main__":
    # Test with a simple example
    test_request = """
    Create a simple pentest lab with:
    - External zone: A Kali attacker machine
    - Internal zone: A Redis server
    - Connect them through a router
    """

    run(test_request)
