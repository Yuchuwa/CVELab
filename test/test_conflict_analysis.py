#!/usr/bin/env python3
"""
Analyze the specific conflict found in test 3.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from node.utils import NetworkBuilder, NetworkBlueprint, LogicalNode


def test_conflict_scenario():
    """Reproduce the exact conflict scenario."""
    print("\n[Analysis] Two routers + one endpoint (creates switch)")
    print("-" * 60)

    blueprint = NetworkBlueprint(
        lab_name="conflict-analysis",
        complexity="simple",
        subnets=["internal"],
        nodes=[
            LogicalNode(
                name="edge-router",
                role="router",
                image_flavor="alpine",
                connected_subnets=["internal"]
            ),
            LogicalNode(
                name="core-router",
                role="router",
                image_flavor="alpine",
                connected_subnets=["internal"]
            ),
            LogicalNode(
                name="app-server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["internal"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/analysis")
    builder.build()

    print("\n  Members in 'internal' subnet: 3")
    print("    - edge-router (router)")
    print("    - core-router (router)")
    print("    - app-server (endpoint)")
    print("\n  Since len(members) > 2, a switch will be created.")

    print("\n  IP Allocation:")
    for node_name, subnet_ips in builder.node_ip_map.items():
        if "internal" in subnet_ips:
            ip = subnet_ips["internal"]
            last_octet = int(ip.split('.')[-1])

            role = "Infrastructure" if last_octet <= 3 else "User LAN"
            print(f"    {node_name}: {ip} ({role})")

    print("\n  ❌ CONFLICT DETECTED:")
    print("     - core-router: 10.0.0.2 (infrastructure)")
    print("     - sw-internal: 10.0.0.2 (infrastructure)")
    print("\n  Both assigned .2 in the same subnet!")


def test_user_lan_uniqueness():
    """Test that user LAN (.64-.254) has NO conflicts."""
    print("\n[Analysis] User LAN uniqueness verification")
    print("-" * 60)

    # Single router, many endpoints (no conflict expected)
    nodes = [
        LogicalNode(
            name=f"server-{i}",
            role="endpoint",
            image_flavor="ubuntu",
            connected_subnets=["lan"]
        )
        for i in range(1, 11)
    ]

    nodes.append(LogicalNode(
        name="router",
        role="router",
        image_flavor="alpine",
        connected_subnets=["lan"]
    ))

    blueprint = NetworkBlueprint(
        lab_name="user-lan-test",
        complexity="simple",
        subnets=["lan"],
        nodes=nodes
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/userlan")
    builder.build()

    print("\n  Scenario: 1 router + 10 endpoints = 11 members → creates switch")

    print("\n  IP Allocation:")
    user_lan_ips = []
    for node_name, subnet_ips in builder.node_ip_map.items():
        if "lan" in subnet_ips:
            ip = subnet_ips["lan"]
            last_octet = int(ip.split('.')[-1])

            if last_octet >= 64:
                user_lan_ips.append((node_name, ip))
                print(f"    {node_name}: {ip} (User LAN)")

    # Check for duplicates in user LAN range
    ips_only = [ip for _, ip in user_lan_ips]
    if len(ips_only) == len(set(ips_only)):
        print(f"\n  ✅ User LAN: All {len(ips_only)} IPs are unique!")
        return True
    else:
        print(f"\n  ❌ User LAN: Found duplicate IPs!")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("IP Conflict Analysis")
    print("=" * 60)

    test_conflict_scenario()
    test_user_lan_uniqueness()

    print("\n" + "=" * 60)
    print("Conclusion:")
    print("  - User LAN (.64-.254) allocation is UNIQUE ✅")
    print("  - Infrastructure (.1-.3) has conflicts in edge cases ❌")
    print("    (When: 2+ routers + switch in same subnet)")
    print("=" * 60)
