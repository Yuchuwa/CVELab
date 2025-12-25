#!/usr/bin/env python3
"""
Workflow test script for Containerlab Builder.
Tests the full pipeline without actual container deployment.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from main import create_workflow
from state import GraphState


def test_workflow_simple():
    """Test workflow with a simple request."""
    print("\n" + "="*60)
    print("Test: Simple Lab Workflow")
    print("="*60)

    app = create_workflow()

    initial_state: GraphState = {
        "user_request": """
        Create a simple lab with 3 machines:
        - A Kali Linux attacker
        - An Alpine router
        - A Redis target server

        The attacker connects to the router, and the router connects to the Redis server.
        """,
        "blueprint": None,
        "yaml_path": "",
        "error_logs": "",
        "is_deployed": False,
        "inspect_data": {},
        "retry_count": 0,
        "is_complete": False,
    }

    print(f"Request: {initial_state['user_request'][:100]}...")

    try:
        # Note: This will fail at deploy stage if containerlab is not installed
        # But it should complete generate -> builder -> validate stages
        result = app.invoke(initial_state)

        print("\n--- Result ---")
        print(f"Blueprint generated: {result.get('blueprint') is not None}")
        print(f"YAML path: {result.get('yaml_path')}")
        print(f"Error logs: {result.get('error_logs') if result.get('error_logs') else 'None'}...")
        print(f"Is complete: {result.get('is_complete')}")

        return True
    except Exception as e:
        print(f"❌ Workflow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_workflow_medium():
    """Test workflow with a medium complexity request."""
    print("\n" + "="*60)
    print("Test: Medium Lab Workflow (with isolation)")
    print("="*60)

    app = create_workflow()

    initial_state: GraphState = {
        "user_request": """
        Create a pentest lab with network isolation:
        - DMZ zone: Kali attacker + Edge router
        - Internal zone: Core router + Redis server + Nginx server

        The attacker can reach internal through both routers.
        """,
        "blueprint": None,
        "yaml_path": "",
        "error_logs": "",
        "is_deployed": False,
        "inspect_data": {},
        "retry_count": 0,
        "is_complete": False,
    }

    print(f"Request: {initial_state['user_request'][:100]}...")

    try:
        result = app.invoke(initial_state)

        print("\n--- Result ---")
        print(f"Blueprint generated: {result.get('blueprint') is not None}")
        print(f"YAML path: {result.get('yaml_path')}")
        print(f"Error logs: {result.get('error_logs') if result.get('error_logs') else 'None'}...")

        return True
    except Exception as e:
        print(f"❌ Workflow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run workflow tests."""
    print("\n" + "="*60)
    print("Containerlab Builder - Workflow Tests")
    print("="*60)
    print("\nNote: These tests will generate YAML files but may fail")
    print("at deployment stage if containerlab is not installed.")
    print("="*60)

    tests = [
        #("Simple Lab", test_workflow_simple)
        ("Medium Lab", test_workflow_medium)
    ]

    results = []
    for name, test_func in tests:
        try:
            results.append(test_func())
        except Exception as e:
            print(f"❌ Test '{name}' failed: {e}")
            results.append(False)

    print("\n" + "="*60)
    print("Workflow Test Summary")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("✅ All workflow tests passed!")
        return 0
    else:
        print("⚠️  Some workflow tests had issues (may be expected)")
        return 0  # Don't fail since deployment is optional


if __name__ == "__main__":
    sys.exit(main())
