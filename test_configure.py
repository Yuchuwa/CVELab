#!/usr/bin/env python3
"""
Test script to verify configure.py logic with existing clab environment.
Note: configure.py reads YAML content from yaml_path, not from state.
"""
import json
import os
from node.configure import configure
from state import GraphState

# Simulated state with existing clab inspect data
# Note: NO yaml_content needed - configure reads from yaml_path
state: GraphState = {
    "user_request": "test configure",
    "yaml_path": "./clab_out/simple-router-lab.clab.yml",
    "blueprint": None,
    "error_logs": "",
    "is_deployed": True,
    "inspect_data": {
        "simple-router-lab": [
            {
                "lab_name": "simple-router-lab",
                "labPath": "clab_out/simple-router-lab.clab.yml",
                "absLabPath": "/home/wolf/Desktop/containerlab_builder/clab_out/simple-router-lab.clab.yml",
                "name": "clab-simple-router-lab-attacker",
                "container_id": "b64f9ad59e2e",
                "image": "kalilinux/kali-rolling:latest",
                "kind": "linux",
                "state": "running",
                "status": "Up 11 minutes",
                "ipv4_address": "172.20.20.2/24",
                "ipv6_address": "3fff:172:20:20::2/64",
                "owner": "wolf"
            },
            {
                "lab_name": "simple-router-lab",
                "labPath": "clab_out/simple-router-lab.clab.yml",
                "absLabPath": "/home/wolf/Desktop/containerlab_builder/clab_out/simple-router-lab.clab.yml",
                "name": "clab-simple-router-lab-redis-target",
                "container_id": "3419dc4c7a94",
                "image": "redis",
                "kind": "linux",
                "state": "running",
                "status": "Up 11 minutes",
                "ipv4_address": "172.20.20.3/24",
                "ipv6_address": "3fff:172:20:20::3/64",
                "owner": "wolf"
            },
            {
                "lab_name": "simple-router-lab",
                "labPath": "clab_out/simple-router-lab.clab.yml",
                "absLabPath": "/home/wolf/Desktop/containerlab_builder/clab_out/simple-router-lab.clab.yml",
                "name": "clab-simple-router-lab-router",
                "container_id": "980948830b05",
                "image": "alpine:latest",
                "kind": "linux",
                "state": "running",
                "status": "Up 11 minutes",
                "ipv4_address": "172.20.20.4/24",
                "ipv6_address": "3fff:172:20:20::4/64",
                "owner": "wolf"
            }
        ]
    },
    "retry_count": 0,
    "is_complete": False
}

if __name__ == "__main__":
    print("Testing configure.py with existing clab environment...")
    print("="*60)
    print(json.dumps(state["inspect_data"], indent=2))
    print("="*60)

    yaml_path = state["yaml_path"]
    if os.path.exists(yaml_path):
        print(f"\n✅ YAML file found: {yaml_path}")
    else:
        print(f"\n⚠️ YAML file NOT found: {yaml_path}")
        print("   configure will skip expected config (exec commands will be empty)")

    result = configure(state)
    print("\nConfigure result:", result)
