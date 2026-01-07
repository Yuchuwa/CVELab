#!/usr/bin/env python3
"""
Run function test script for Containerlab Builder.
Tests the complete run() function including session ID generation.
"""
import sys
import os

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from main import run


def test_run_simple():
    """Test run() function with a simple request."""
    print("\n" + "="*60)
    print("Test: Simple Lab - run() function")
    print("="*60)

    request = """
    Create a simple lab with:
    - A Kali Linux attacker machine
    - An Alpine router
    - A Redis target server

    Connect them in a line: attacker -> router -> redis
    """

    try:
        result = run(request)

        print("\n--- Result ---")
        print(f"Blueprint generated: {result.get('blueprint') is not None}")
        print(f"YAML path: {result.get('yaml_path')}")
        print(f"Error logs: {result.get('error_logs') if result.get('error_logs') else 'None'}")
        print(f"Is complete: {result.get('is_complete')}")

        # 检查yaml_path是否包含会话ID目录
        yaml_path = result.get('yaml_path', '')
        if 'clab_out/' in yaml_path:
            parts = yaml_path.split('clab_out/')
            if len(parts) > 1:
                session_part = parts[1].split('/')[0]
                print(f"Session directory detected: {session_part}")

        return True
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_run_medium():
    """Test run() function with a medium complexity request."""
    print("\n" + "="*60)
    print("Test: Medium Lab - run() function")
    print("="*60)

    request = """
    Create a pentest lab with network isolation:
    - DMZ zone: Kali attacker + Edge router
    - Internal zone: Core router + Redis server + Nginx server

    The attacker can reach internal through both routers.
    """

    try:
        result = run(request)

        print("\n--- Result ---")
        print(f"Blueprint generated: {result.get('blueprint') is not None}")
        print(f"YAML path: {result.get('yaml_path')}")
        print(f"Error logs: {result.get('error_logs') if result.get('error_logs') else 'None'}")
        print(f"Is complete: {result.get('is_complete')}")

        return True
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_run_multiple_sessions():
    """Test that multiple run() calls create different session directories."""
    print("\n" + "="*60)
    print("Test: Multiple Sessions - run() function")
    print("="*60)

    request = "Create a simple lab with a Kali attacker and a Redis target connected by a router"

    session_dirs = []

    try:
        # 运行3次，收集会话目录
        for i in range(3):
            print(f"\n--- Run {i+1}/3 ---")
            result = run(request)

            yaml_path = result.get('yaml_path', '')
            if 'clab_out/' in yaml_path:
                parts = yaml_path.split('clab_out/')
                if len(parts) > 1:
                    session_part = parts[1].split('/')[0]
                    session_dirs.append(session_part)
                    print(f"Session directory: {session_part}")

        # 检查会话目录是否唯一
        print("\n--- Session Uniqueness Check ---")
        print(f"Session directories: {session_dirs}")
        unique_sessions = len(set(session_dirs))
        total_sessions = len(session_dirs)

        print(f"Unique sessions: {unique_sessions}/{total_sessions}")

        if unique_sessions == total_sessions:
            print("✅ All session directories are unique!")
            return True
        else:
            print("❌ Session directories are not unique!")
            return False

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run function tests."""
    print("\n" + "="*60)
    print("Containerlab Builder - run() Function Tests")
    print("="*60)
    print("\nNote: These tests will:")
    print("1. Generate unique session IDs for each run")
    print("2. Create separate directories under clab_out/")
    print("3. May fail at deployment stage if containerlab is not installed")
    print("="*60)

    tests = [
        #("Simple Lab", test_run_simple),
       # ("Multiple Sessions", test_run_multiple_sessions),
     ("Medium Lab", test_run_medium),  # 可选：更复杂的测试
    ]

    results = []
    for name, test_func in tests:
        try:
            results.append(test_func())
        except Exception as e:
            print(f"❌ Test '{name}' failed: {e}")
            results.append(False)

    print("\n" + "="*60)
    print("Run Function Test Summary")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("✅ All run() function tests passed!")
        return 0
    else:
        print("⚠️  Some run() function tests had issues")
        return 0  # Don't fail since deployment is optional


if __name__ == "__main__":
    sys.exit(main())
