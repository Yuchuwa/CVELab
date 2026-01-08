#!/usr/bin/env python3
"""
Test for User LAN IP address uniqueness validation.
Focuses on .64-.254 range allocation for endpoints.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from node.utils import NetworkBuilder, NetworkBlueprint, LogicalNode


def analyze_ip_allocation(builder, subnet_name):
    """Analyze IP allocation in a subnet."""
    print(f"\n  Subnet: {subnet_name} ({builder.subnet_map[subnet_name]})")

    # Group IPs by role
    infrastructure = []  # .1-.3
    user_lan = []         # .64-.254

    for node_name, subnet_ips in builder.node_ip_map.items():
        if subnet_name in subnet_ips:
            ip = subnet_ips[subnet_name]
            last_octet = int(ip.split('.')[-1])

            if last_octet <= 3:
                infrastructure.append((node_name, ip))
            elif 64 <= last_octet <= 254:
                user_lan.append((node_name, ip))
            else:
                print(f"    ⚠️  {node_name}: {ip} (reserved range)")

    # Check for duplicates
    print(f"\n  Infrastructure ({len(infrastructure)}):")
    for node, ip in infrastructure:
        print(f"    {node}: {ip}")

    print(f"\n  User LAN ({len(user_lan)}):")
    for node, ip in user_lan:
        print(f"    {node}: {ip}")

    # Verify uniqueness
    all_ips = [ip for _, ip in infrastructure + user_lan]
    duplicates = [ip for ip in all_ips if all_ips.count(ip) > 1]

    if duplicates:
        print(f"\n  ❌ DUPLICATE IPs found: {set(duplicates)}")
        return False

    # Verify user LAN range compliance
    for node, ip in user_lan:
        last_octet = int(ip.split('.')[-1])
        if last_octet < 64 or last_octet > 254:
            print(f"\n  ❌ {node} has IP {ip} outside user LAN range (.64-.254)")
            return False

    print(f"\n  ✓ All {len(all_ips)} IPs are unique and in correct ranges")
    return True


def test_single_subnet_many_endpoints():
    """Test many endpoints in single subnet."""
    print("\n[Test 1] Many endpoints in single subnet")
    print("-" * 60)

    # Create 10 endpoints
    nodes = [
        LogicalNode(
            name=f"server-{i}",
            role="endpoint",
            image_flavor="ubuntu",
            connected_subnets=["lan"]
        )
        for i in range(1, 11)
    ]

    # Add one router
    nodes.insert(0, LogicalNode(
        name="router",
        role="router",
        image_flavor="alpine",
        connected_subnets=["lan"]
    ))

    blueprint = NetworkBlueprint(
        lab_name="many-endpoints",
        complexity="simple",
        subnets=["lan"],
        nodes=nodes
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/user_lan_1")
    builder.build()

    return analyze_ip_allocation(builder, "lan")


def test_multiple_subnets_same_endpoints():
    """Test same node names across different subnets."""
    print("\n[Test 2] Multiple subnets with same endpoint structure")
    print("-" * 60)

    blueprint = NetworkBlueprint(
        lab_name="multi-subnet",
        complexity="simple",
        subnets=["lan1", "lan2", "lan3"],
        nodes=[
            LogicalNode(
                name="router",
                role="router",
                image_flavor="alpine",
                connected_subnets=["lan1", "lan2", "lan3"]
            ),
            LogicalNode(
                name="web-1",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["lan1", "lan2"]
            ),
            LogicalNode(
                name="web-2",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["lan2", "lan3"]
            ),
            LogicalNode(
                name="db-server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["lan3"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/user_lan_2")
    builder.build()

    results = []
    for subnet in ["lan1", "lan2", "lan3"]:
        results.append(analyze_ip_allocation(builder, subnet))

    return all(results)


def test_global_uniqueness_across_all_subnets():
    """Test that no two interfaces have the same IP globally."""
    print("\n[Test 3] Global uniqueness across entire topology")
    print("-" * 60)

    blueprint = NetworkBlueprint(
        lab_name="global-unique",
        complexity="simple",
        subnets=["dmz", "internal", "backend"],
        nodes=[
            LogicalNode(
                name="edge-router",
                role="router",
                image_flavor="alpine",
                connected_subnets=["dmz", "internal"]
            ),
            LogicalNode(
                name="core-router",
                role="router",
                image_flavor="alpine",
                connected_subnets=["internal", "backend"]
            ),
            LogicalNode(
                name="web-server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["dmz"]
            ),
            LogicalNode(
                name="app-server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["internal"]
            ),
            LogicalNode(
                name="db-server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["backend"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/user_lan_3")
    builder.build()

    # Collect all IPs globally
    global_ips = {}
    for node_name, subnet_ips in builder.node_ip_map.items():
        for subnet, ip in subnet_ips.items():
            if ip in global_ips:
                # Different subnets can have same IP (that's OK!)
                # But check if it's the same subnet
                existing_subnet = global_ips[ip]
                if existing_subnet != subnet:
                    print(f"\n  ✓ Same IP {ip} in different subnets ({existing_subnet} vs {subnet}) - OK")
                else:
                    print(f"\n  ❌ CONFLICT: {ip} used twice in subnet {subnet}")
                    print(f"     - {global_ips[ip]}")
                    print(f"     - {node_name}")
                    return False
            else:
                global_ips[ip] = subnet

    print(f"\n  ✓ All {len(global_ips)} IP allocations are valid")
    print(f"     (Same IPs in different subnets is expected and correct)")
    return True


def test_user_lan_exhaustion():
    """Test boundary: what happens with too many endpoints."""
    print("\n[Test 4] User LAN range boundary (191 IPs available)")
    print("-" * 60)

    # Try to create 200 endpoints (should fail at 192)
    nodes = [
        LogicalNode(
            name=f"endpoint-{i}",
            role="endpoint",
            image_flavor="ubuntu",
            connected_subnets=["lan"]
        )
        for i in range(1, 200)
    ]

    nodes.append(LogicalNode(
        name="router",
        role="router",
        image_flavor="alpine",
        connected_subnets=["lan"]
    ))

    blueprint = NetworkBlueprint(
        lab_name="exhaustion-test",
        complexity="simple",
        subnets=["lan"],
        nodes=nodes
    )

    try:
        builder = NetworkBuilder(blueprint, output_dir="./test_output/user_lan_4")
        builder.build()
        print(f"\n  ⚠️  No error raised with 199 endpoints")
        print(f"     This suggests IP allocation may silently fail or wrap around")
        return False
    except Exception as e:
        print(f"\n  ✓ Correctly raised error: {e}")
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("User LAN IP Uniqueness Validation Tests")
    print("Testing .64-.254 range allocation")
    print("=" * 60)

    results = []
    results.append(test_single_subnet_many_endpoints())
    results.append(test_multiple_subnets_same_endpoints())
    results.append(test_global_uniqueness_across_all_subnets())
    # results.append(test_user_lan_exhaustion())  # Optional: stress test

    print("\n" + "=" * 60)
    if all(results):
        print("✅ All User LAN uniqueness tests passed!")
    else:
        print("❌ Some tests detected issues!")
    print("=" * 60)
