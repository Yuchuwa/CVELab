#!/usr/bin/env python3
"""Test for IP address uniqueness validation."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from node.utils import NetworkBuilder, NetworkBlueprint, LogicalNode


def test_two_routers_with_switch():
    """Test potential conflict: 2 routers + 1 endpoint (creates switch)."""
    print("\n[Test] Two routers with switch - Checking for .2 conflict")
    print("-" * 60)

    blueprint = NetworkBlueprint(
        lab_name="conflict-test",
        complexity="simple",
        subnets=["internal"],
        nodes=[
            LogicalNode(
                name="router-1",
                role="router",
                image_flavor="alpine",
                connected_subnets=["internal"]
            ),
            LogicalNode(
                name="router-2",
                role="router",
                image_flavor="alpine",
                connected_subnets=["internal"]
            ),
            LogicalNode(
                name="server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["internal"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/conflict")
    builder.build()

    # Collect all IPs
    all_ips = {}
    for node_name, subnet_ips in builder.node_ip_map.items():
        for subnet, ip in subnet_ips.items():
            print(f"  {node_name} ({subnet}): {ip}")
            if ip in all_ips:
                print(f"\n  ❌ CONFLICT: IP {ip} assigned to both {all_ips[ip]} and {node_name}!")
                return False
            all_ips[ip] = node_name

    print("\n  ✓ No IP conflicts detected")
    return True


def test_two_routers_point_to_point():
    """Test two routers in point-to-point (no switch)."""
    print("\n[Test] Two routers point-to-point")
    print("-" * 60)

    blueprint = NetworkBlueprint(
        lab_name="p2p-test",
        complexity="simple",
        subnets=["link"],
        nodes=[
            LogicalNode(
                name="router-a",
                role="router",
                image_flavor="alpine",
                connected_subnets=["link"]
            ),
            LogicalNode(
                name="router-b",
                role="router",
                image_flavor="alpine",
                connected_subnets=["link"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/p2p")
    builder.build()

    all_ips = {}
    for node_name, subnet_ips in builder.node_ip_map.items():
        for subnet, ip in subnet_ips.items():
            print(f"  {node_name} ({subnet}): {ip}")
            if ip in all_ips:
                print(f"\n  ❌ CONFLICT: IP {ip} assigned to both {all_ips[ip]} and {node_name}!")
                return False
            all_ips[ip] = node_name

    print("\n  ✓ No IP conflicts detected")
    return True


def test_global_uniqueness():
    """Test that IPs are unique across entire topology."""
    print("\n[Test] Global IP uniqueness across all subnets")
    print("-" * 60)

    blueprint = NetworkBlueprint(
        lab_name="global-test",
        complexity="simple",
        subnets=["net1", "net2", "net3"],
        nodes=[
            LogicalNode(
                name="router-1",
                role="router",
                image_flavor="alpine",
                connected_subnets=["net1", "net2"]
            ),
            LogicalNode(
                name="router-2",
                role="router",
                image_flavor="alpine",
                connected_subnets=["net2", "net3"]
            ),
            LogicalNode(
                name="endpoint-1",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["net1"]
            ),
            LogicalNode(
                name="endpoint-2",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["net3"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/global")
    builder.build()

    all_ips = {}
    for node_name, subnet_ips in builder.node_ip_map.items():
        for subnet, ip in subnet_ips.items():
            print(f"  {node_name} ({subnet}): {ip}")
            if ip in all_ips:
                print(f"\n  ❌ CONFLICT: IP {ip} assigned to both:")
                print(f"     - {all_ips[ip]} ({all_ips[ip].get(subnet, '?')})")
                print(f"     - {node_name} ({subnet})")
                return False
            all_ips[ip] = node_name

    print("\n  ✓ No IP conflicts detected")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("IP Uniqueness Validation Tests")
    print("=" * 60)

    results = []
    results.append(test_two_routers_with_switch())
    results.append(test_two_routers_point_to_point())
    results.append(test_global_uniqueness())

    print("\n" + "=" * 60)
    if all(results):
        print("✅ All uniqueness tests passed!")
    else:
        print("❌ Some tests detected IP conflicts!")
    print("=" * 60)
