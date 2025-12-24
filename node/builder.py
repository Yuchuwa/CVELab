from state import GraphState
from .utils import NetworkBuilder

def builder_node(state: GraphState):
    print("\n👷 [Builder] Constructing YAML from blueprint...")

    blueprint = state.get('blueprint')
    if blueprint is None:
        error_msg = "No blueprint provided to builder"
        print(f"   -> ❌ {error_msg}")
        return {"error_logs": error_msg}

    try:
        builder = NetworkBuilder(blueprint)
        yaml_path = builder.build()
        print(f"   -> YAML generated at: {yaml_path}")
        return {"yaml_path": yaml_path, "error_logs": ""}
    except Exception as e:
        return {"error_logs": f"Builder Error: {str(e)}"}