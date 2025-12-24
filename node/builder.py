from state import GraphState
from .utils import NetworkBuilder
def builder_node(state: GraphState):
    print("\n👷 [Builder] Constructing YAML from blueprint...")
    try:
        builder = NetworkBuilder(state['blueprint'])
        yaml_path=builder.build()
        print(f"   -> YAML generated at: {yaml_path}")
        return {"yaml_path": yaml_path, "error_logs": ""}
    except Exception as e:
        return {"error_logs": f"Builder Error: {str(e)}"}