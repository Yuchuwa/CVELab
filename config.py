import os
from dotenv import load_dotenv
load_dotenv()


# --- CONFIGURATION ---
# Ensure your API Key is set in your environment variables
# os.environ["OPENAI_API_KEY"] = "sk-..."

LLM_MODEL = "MiniMax-M2.1-free" 
BASE_URL= os.getenv("LLM_BASE_URL", None)  # Optional custom base URL
API_KEY= os.getenv("LLM_API_KEY", None)  # Optional custom API Key