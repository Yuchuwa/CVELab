
from langchain.chat_models import init_chat_model
from langchain.agents import create_agent

from state import GraphState
from .utils import NetworkBlueprint  # 假设你的 Pydantic 模型定义在这里
from config import LLM_MODEL,BASE_URL,API_KEY
from containerlab_tools import clab_lifecycle_tool,node_config_tool
# 设置最大重试次数，防止死循环
MAX_RETRIES = 3

def fixer(state: GraphState):
    """
    Fixer Node: Analyzes error logs and patches the NetworkBlueprint.
    """
    print(f"\n🚑 [Fixer] Activated. Analyzing errors (Attempt {state.get('retry_count', 0) + 1}/{MAX_RETRIES})...")
    
    # 1. 熔断机制
    current_retries = state.get("retry_count", 0)
    if current_retries >= MAX_RETRIES:
        print("❌ [Fixer] Max retries reached. Stopping execution.")
        # 这里可以选择抛出异常，或者返回一个标记让流程结束
        raise RuntimeError(f"Failed to fix topology after {MAX_RETRIES} attempts. Last error: {state.get('error_logs')}")

    # 2. 获取上下文
    user_request = state.get("user_request")
    error_logs = state.get("error_logs", "Unknown Error")
    # 获取当前的蓝图 (如果是 Pydantic 对象则转 dict，如果是 dict 则直接用)
    current_bp = state.get("blueprint")
    if current_bp is not None and hasattr(current_bp, "model_dump_json"):
        current_bp_json = current_bp.model_dump_json()
    else:
        current_bp_json = str(current_bp) if current_bp else "No blueprint available"

    # 3. 初始化 LLM
    # 建议使用 GPT-4o，因为 Debug 需要较强的逻辑推理能力.
    model=init_chat_model(
        model_provider="openai",
        model=LLM_MODEL,
        temperature=0.6,
        base_url=BASE_URL,
        api_key=API_KEY
    )
    # 4. 设计 "运维专家" Prompt - 使用 f-string 传递动态参数
    system_prompt = f"""
    You are an expert Network Reliability Engineer (NRE) specializing in Containerlab and Docker.
    Your job is to fix a broken network topology design based on deployment error logs.

    ### INPUT CONTEXT
    1. **User Goal**: {user_request}
    2. **Current Design (JSON)**: {current_bp_json}
    3. **Error Logs**: {error_logs}
    4. **Retry Count**: {current_retries + 1}/{MAX_RETRIES}

    ### DIAGNOSIS PLAYBOOK (Common Errors & Fixes)
    
    - **Error: "manifest for ... not found" / "pull access denied"**
      -> **Diagnosis**: The Docker image name is incorrect or does not exist.
      -> **Fix**: Change the `image_flavor` of the failing node to a standard one (e.g., change specific 'vulfocus/...' to 'alpine' or 'ubuntu' if the vuln image is broken, OR try to correct the tag).
    
    - **Error: "Duplicate endpoint" / "interface used multiple times"**
      -> **Diagnosis**: Two nodes are trying to connect to the same port on a router, or the physical wiring is impossible.
      -> **Fix**: Check the `connected_subnets`. If multiple nodes are in the same subnet, ensure the logical design allows the Builder to inject a switch (usually this is handled by Builder, but maybe you defined a router as an endpoint?).
      
    - **Error: "bridge ... does not exist"**
      -> **Diagnosis**: Issue with bridge creation.
      -> **Fix**: This is often a system issue, but simplifying the subnet structure might help. Verify logical node roles.

    - **Error: "IP address conflict" / "File exists"**
      -> **Diagnosis**: IPAM logic collision.
      -> **Fix**: (Rarely happens with UniversalBuilder) but if so, ensure nodes have distinct roles.

    ### TASK
    1. Analyze the error log carefully.
    2. Modify the `Current Design` JSON **minimally** to resolve the specific error.
    3. Do NOT change parts of the design that are working fine.
    4. Ensure strict adherence to the output schema.

    """
    fixer_agent=create_agent(
        model=model,
        system_prompt=system_prompt,
        tools=[clab_lifecycle_tool,node_config_tool],
        response_format=NetworkBlueprint
    )
    try:
        print(f"   -> ✅ Fix proposed. Retrying build...")
        result = fixer_agent.invoke({"messages": [{"role": "user", "content": "Fix the broken network topology design based on deployment error logs."}]})

        # Extract blueprint from result - similar to generate.py
        # According to LangChain docs, when using response_format, result["structured_response"] contains the structured output
        if "structured_response" in result:
            new_blueprint = result["structured_response"]
        else:
            raise ValueError(f"Fixer agent did not return a valid blueprint. Keys: {list(result.keys())}")

        # 6. 返回更新后的状态
        return {
            "blueprint": new_blueprint,      # 更新蓝图
            "error_logs": "",                # 清空错误日志 (关键！)
            "retry_count": current_retries + 1, # 增加重试计数
            # 保留其他状态不变
        }

    except Exception as e:
        print(f"   -> ❌ Fixer crashed: {e}")
        import traceback
        traceback.print_exc()
        # 如果 Fixer 自己都挂了，为了防止死循环，增加计数并保留错误
        return {
            "retry_count": current_retries + 1,
            "error_logs": f"Fixer Internal Error: {str(e)}"
        }
