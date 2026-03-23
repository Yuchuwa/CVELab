import pandas as pd
import io # Still useful if you want to test with string in future, but not for file path
import os # To check file existence
from typing import List, Dict, Optional
from langchain.tools import tool
from pydantic import BaseModel, Field

# 1. Prepare the Data (Loading from a CSV file)
class VulnKnowledgeBase:
    def __init__(self, csv_filepath: str):
        if not os.path.exists(csv_filepath):
            raise FileNotFoundError(f"CSV file not found at: {csv_filepath}")

        self.df = pd.read_csv(csv_filepath)
        # Ensure string columns are strings and handle NaNs by filling with empty strings
        self.df.fillna('', inplace=True)
        print(f"Successfully loaded {len(self.df)} vulnerability entries from {csv_filepath}")

    def search(self, query: str) -> List[Dict]:
        """
        Search the dataframe for rows matching the query.
        Search order: CVE > Type > Name/Description.
        """
        query = query.lower().strip()
        results = []

        # 1. Exact or Partial CVE Match (High Priority)
        if "cve-" in query:
            cve_matches = self.df[self.df['CVE'].str.lower().str.contains(query)]
            if not cve_matches.empty:
                return cve_matches.to_dict(orient='records')

        # 2. Type Match (e.g., 'RCE', 'SQL Injection', 'XSS')
        type_matches = self.df[self.df['Type'].str.lower().str.contains(query)]
        if not type_matches.empty:
            return type_matches.to_dict(orient='records')

        # 3. General Keyword Match (Name or Description)
        mask = (
            self.df['Name'].str.lower().str.contains(query) |
            self.df['Description'].str.lower().str.contains(query)
        )
        matches = self.df[mask]

        return matches.to_dict(orient='records')

# Specify the path to your CSV file (absolute path based on script location)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
CSV_FILE_PATH = os.path.join(_PROJECT_ROOT, 'source/vulhub_cves_20260114.csv')

# Initialize the Knowledge Base with the file path
kb = VulnKnowledgeBase(CSV_FILE_PATH)

# 2. Define Input Schema for the Tool
class VulnSearchInput(BaseModel):
    query: str = Field(description="The vulnerability name, CVE ID, type, or keyword to search for (e.g., 'CVE-2023-46604', 'ActiveMQ', or 'RCE').")

# 3. Create the LangChain Tool
@tool("search_vulnerability_image", args_schema=VulnSearchInput)
def search_vulnerability_image(query: str) -> str:
    """
    Search for vulnerability details by CVE ID or software name from local CSV.

    Returns:
        A string containing the vulnerability description and the
        'Vulhub Path' which MUST be used in the NetworkBlueprint.
    """
    results = kb.search(query)

    if not results:
        return f"No vulnerabilities found matching '{query}' in the local database."

    # Format the output for the LLM to understand easily
    response = f"Found {len(results)} matching entries:\n"
    for idx, r in enumerate(results):
        response += f"\n--- Result {idx + 1} ---\n"
        response += f"Name: {r['Name']}\n"
        response += f"CVE: {r['CVE']}\n"
        response += f"Description: {r['Description']}\n"
        response += f"Vulhub Path: {r['Path']}\n"
        response += f"Type: {r['Type']}\n"
        response += f"Network role: {r['Role']}\n"
        response += f"Runtime Language: {r['Runtime_lang']}\n"
    return response



# --- Example Usage Logic (Not part of the tool, just verification) ---
if __name__ == "__main__":
    print(f"--- Testing vulnerability search tool with CSV file: {CSV_FILE_PATH} ---")

    print("\nTest 1: Search by CVE ID 'CVE-2023-46604'")
    print(search_vulnerability_image.invoke({"query": "CVE-2023-46604"}))

    print("\nTest 2: Search by Software Name 'ActiveMQ'")
    print(search_vulnerability_image.invoke({"query": "ActiveMQ"}))

    print("\nTest 3: Search by Type 'RCE'")
    print(search_vulnerability_image.invoke({"query": "RCE"}))

    print("\nTest 4: Search by Type 'SQL Injection'")
    print(search_vulnerability_image.invoke({"query": "SQL Injection"}))

    print("\nTest 5: Search for a non-existent CVE")
    print(search_vulnerability_image.invoke({"query": "CVE-9999-9999"}))