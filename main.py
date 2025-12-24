from state import GraphState
from langgraph.graph import StateGraph, START, END
from node.generate import generate
from node.deploy import deploy
from node.configure import configure
from node.builder import builder_node
from node.validate import validator_node
from node.fixer import fixer


def main():
    print("Hello from containerlab-builder!")

    workflow = StateGraph(GraphState)
    workflow.add_node("generate", generate)
    workflow.add_node("builder",builder_node)
    workflow.add_node("validate",validator_node)
    workflow.add_node("deploy", deploy)
    workflow.add_node("configure", configure)
    workflow.add_node("fixer",fixer)

    workflow.set_entry_point("generator")
    def check_build_errors(state):
        return "validator" if not state.get("error_logs") else "fixer"
    
    def check_validation_errors(state):
        return "deployer" if not state.get("error_logs") else "fixer"
    
    def check_deploy_errors(state):
        return "configurator" if state.get("error_logs") else "fixer"
    
    workflow.add_edge("generator", "builder")
    workflow.add_conditional_edges("builder", check_build_errors)
    workflow.add_conditional_edges("validator", check_validation_errors)
    workflow.add_conditional_edges("deployer", check_deploy_errors)

    workflow.add_edge("fixer", "builder") # Fixer always goes back to build
    workflow.add_edge("configurator", END)

    app = workflow.compile()

    return app


if __name__ == "__main__":
    app = main()
