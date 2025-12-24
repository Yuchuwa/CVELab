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
        Prioritize CVE ID match, then Name/Description match.
        """
        query = query.lower().strip()
        results = []
        
        # 1. Exact or Partial CVE Match (High Priority)
        if "cve-" in query:
            cve_matches = self.df[self.df['CVE'].str.lower().str.contains(query)]
            if not cve_matches.empty:
                return cve_matches.to_dict(orient='records')

        # 2. General Keyword Match (Name or Description)
        mask = (
            self.df['Name'].str.lower().str.contains(query) | 
            self.df['Description'].str.lower().str.contains(query)
        )
        matches = self.df[mask]
        
        return matches.to_dict(orient='records')

# Specify the path to your CSV file
CSV_FILE_PATH = 'source/20251009-160138-dac310-vuln_list_w_url.csv'

# Initialize the Knowledge Base with the file path
kb = VulnKnowledgeBase(CSV_FILE_PATH)

# 2. Define Input Schema for the Tool
class VulnSearchInput(BaseModel):
    query: str = Field(description="The vulnerability name, CVE ID, or keyword to search for (e.g., 'CVE-2023-46604' or 'ActiveMQ').")

# 3. Create the LangChain Tool
@tool("search_vulnerability_image", args_schema=VulnSearchInput)
def search_vulnerability_image(query: str) -> str:
    """
    Search for vulnerability details by CVE ID or software name.
    
    IMPORTANT: This tool converts raw Vulhub paths into ready-to-use 
    Docker Image names (vulfocus based) for Containerlab.
    
    Returns:
        A string containing the vulnerability description and the 
        'Recommended Docker Image' which MUST be used in the topology YAML.
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
        response += f"Startup Command: {r['Startup']}\n"
        
        # Helper for Agent: Suggest a potential image name based on logic
        # (This is a heuristic. Actual Vulfocus image names may vary slightly,
        # but it gives the LLM a good starting point.)
        cve_underscore = r['CVE'].replace('-', '_').lower()
        potential_image = f"vulfocus/{r['Name'].lower().replace(' ', '')}-{cve_underscore}"
        response += f"Suggestion for Containerlab Image: {potential_image} (Note: Verify existence)\n"
        
    return response



# --- Example Usage Logic (Not part of the tool, just verification) ---
if __name__ == "__main__":
    print(f"--- Testing vulnerability search tool with CSV file: {CSV_FILE_PATH} ---")

    print("\nTest 1: Search by CVE ID 'CVE-2023-46604'")
    print(search_vulnerability_image.invoke({"query": "CVE-2023-46604"}))
    
    print("\nTest 2: Search by Software Name 'ActiveMQ'")
    print(search_vulnerability_image.invoke({"query": "ActiveMQ"}))

    print("\nTest 3: Search for a non-existent CVE")
    print(search_vulnerability_image.invoke({"query": "CVE-9999-9999"}))