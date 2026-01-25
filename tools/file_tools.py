from enum import Enum
from typing import Optional, Literal
from pydantic import BaseModel, Field
from langchain_core.tools import tool


class ReadFileInput(BaseModel):
    file_path: str = Field(
        ...,
        description="Absolute path to the file to read (e.g., '/path/to/file.clab.yml' or '/path/to/config.json')."
    )


@tool("read_file_tool", args_schema=ReadFileInput)
def read_file_tool(file_path: str) -> str:
    """
    Reads the content of a file.

    Use this tool to examine the current content of YAML or JSON configuration files
    before making modifications.

    IMPORTANT:
    - Only read files that you have been explicitly authorized to access
    - Returns the complete file content as a string
    - Use this to analyze the current state before deciding what changes to make
    """
    try:
        # Security check: only allow specific file extensions
        allowed_extensions = ['.yml', '.yaml', '.json']
        if not any(file_path.endswith(ext) for ext in allowed_extensions):
            return f"Error: File must have one of these extensions: {', '.join(allowed_extensions)}"

        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return content

    except FileNotFoundError:
        return f"Error: File '{file_path}' not found."
    except IOError as e:
        return f"Error: Failed to read file '{file_path}': {str(e)}"
    except Exception as e:
        return f"System Error: {str(e)}"


class ModifyFileInput(BaseModel):
    file_path: str = Field(
        ...,
        description="Absolute path to the file to modify (e.g., '/path/to/file.clab.yml' or '/path/to/config.json')."
    )
    new_content: str = Field(
        ...,
        description="The new complete content to write to the file. This should be the full file content, not a patch."
    )

@tool("modify_file_tool", args_schema=ModifyFileInput)
def modify_file_tool(file_path: str, new_content: str) -> str:
    """
    Modifies a file by writing new content to it.

    Use this tool to fix YAML or JSON configuration files after analyzing errors.
    The tool will overwrite the file with the new content.

    IMPORTANT:
    - Provide the COMPLETE new content of the file, not just a diff
    - Ensure YAML/JSON syntax is correct before using this tool
    - Use proper indentation (2 spaces for YAML)
    - For YAML files, ensure all quotes and special characters are properly escaped
    """
    try:
        # Security check: only allow specific file extensions
        allowed_extensions = ['.yml', '.yaml', '.json']
        if not any(file_path.endswith(ext) for ext in allowed_extensions):
            return f"Error: File must have one of these extensions: {', '.join(allowed_extensions)}"

        # Write the new content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        return f"Success: File '{file_path}' has been updated."

    except IOError as e:
        return f"Error: Failed to write file '{file_path}': {str(e)}"
    except Exception as e:
        return f"System Error: {str(e)}"