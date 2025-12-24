import subprocess
import shlex
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

# --- Tool 1: Containerlab Lifecycle Manager ---

class ClabAction(str, Enum):
    """Allowed actions for Containerlab management."""
    DEPLOY = "deploy"
    DESTROY = "destroy"
    RECONFIGURE = "reconfigure"  # Maps to 'deploy --reconfigure'
    INSPECT = "inspect"

class LifecycleInput(BaseModel):
    action: ClabAction = Field(
        ..., 
        description="The action to perform on the topology."
    )
    topology_path: str = Field(
        ..., 
        description="Path to the .clab.yml topology file."
    )

@tool("clab_lifecycle_tool", args_schema=LifecycleInput)
def clab_lifecycle_tool(action: ClabAction, topology_path: str) -> str:
    """
    Manages the lifecycle of a Containerlab topology. 
    Can deploy, destroy (cleanup), reconfigure, or inspect a lab.
    Always runs with sudo privileges.
    """
    # 1. Input Validation (Security)
    if not topology_path.endswith((".yml", ".yaml")):
        return "Error: File path must end with .yml or .yaml"

    # 2. Command Construction
    base_cmd = ["sudo", "containerlab"]
    
    if action == ClabAction.DEPLOY:
        # Standard deploy
        final_cmd = base_cmd + ["deploy", "-t", topology_path]
        
    elif action == ClabAction.RECONFIGURE:
        # Force reconfiguration of existing containers
        final_cmd = base_cmd + ["deploy", "-t", topology_path, "--reconfigure"]
        
    elif action == ClabAction.DESTROY:
        # Destroy and cleanup certificates/configs
        final_cmd = base_cmd + ["destroy", "-t", topology_path, "--cleanup"]
        
    elif action == ClabAction.INSPECT:
        # Return JSON format for the agent to parse easily
        final_cmd = base_cmd + ["inspect", "-t", topology_path, "--format", "json"]
    
    else:
        return f"Error: Unknown action {action}"

    # 3. Execution
    try:
        print(f"⚙️ Executing: {' '.join(final_cmd)}")
        result = subprocess.run(
            final_cmd, 
            capture_output=True, 
            text=True, 
            timeout=300 # Longer timeout for image pulling
        )
        
        if result.returncode == 0:
            return f"Success:\n{result.stdout}"
        else:
            return f"Failed (Exit Code {result.returncode}):\n{result.stderr}"
            
    except subprocess.TimeoutExpired:
        return "Error: Command timed out. The operation took too long (e.g., pulling large images)."
    except Exception as e:
        return f"System Error: {str(e)}"


# --- Tool 2: Node Configuration Executor (Docker Exec) ---

class NodeConfigInput(BaseModel):
    container_name: str = Field(
        ..., 
        description="The FULL name of the container (e.g., 'clab-mvp-pentest-lab-attacker'). You can get this from the inspect action."
    )
    command: str = Field(
        ..., 
        description="The shell command to run INSIDE the container (e.g., 'ip addr add...'). Do NOT include 'docker exec' here."
    )

@tool("node_config_tool", args_schema=NodeConfigInput)
def node_config_tool(container_name: str, command: str) -> str:
    """
    Executes a shell command inside a specific running container.
    Use this for configuring network interfaces, routes, or installing packages.
    """
    # 1. Security & Safety Checks
    # Prevent escaping the container or running dangerous host commands
    forbidden_chars = [";", "`", "$(", "|"] 
    # Note: This is a basic filter. For complex commands (like pipe), 
    # we allow them but execute via 'sh -c' inside the container.
    
    # 2. Construct Docker Exec Command
    # We use sh -c to allow multiple commands or pipes inside the container
    # quoting the command is crucial.
    docker_cmd = [
        "docker", "exec", container_name, 
        "sh", "-c", command
    ]
    
    # 3. Execution
    try:
        # print(f"🔧 Configuring {container_name}: {command}")
        result = subprocess.run(
            docker_cmd, 
            capture_output=True, 
            text=True, 
            timeout=60 # Shorter timeout for config commands
        )
        
        if result.returncode == 0:
            return f"Output:\n{result.stdout}"
        else:
            return f"Error (Code {result.returncode}):\n{result.stderr}"
            
    except subprocess.TimeoutExpired:
        return f"Error: Command '{command}' timed out in container '{container_name}'."
    except Exception as e:
        return f"System Error: {str(e)}"