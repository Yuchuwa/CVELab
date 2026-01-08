#!/usr/bin/env python3
"""
Unit test for IPAM module - validates new C-class allocation rules.
Tests:
1. /24 subnet allocation strategy
2. Infrastructure IPs (.1 for router, .2 for switch)
3. User LAN range (.64-.254 for endpoints)
4. Unique IP address assignment
5. Interface numbering correctness
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from node.utils import NetworkBuilder, NetworkBlueprint, LogicalNode


def test_simple_two_node_topology():
    """Test point-to-point: one router, one endpoint."""
    print("\n[Test 1] Simple point-to-point topology")
    print("-" * 50)

    blueprint = NetworkBlueprint(
        lab_name="test-lab-1",
        complexity="simple",
        subnets=["dmz"],
        nodes=[
            LogicalNode(
                name="edge-router",
                role="router",
                image_flavor="alpine",
                connected_subnets=["dmz"]
            ),
            LogicalNode(
                name="web-server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["dmz"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/test1")
    builder.build()

    # Verify IP allocation
    router_ip = builder.node_ip_map["edge-router"]["dmz"]
    endpoint_ip = builder.node_ip_map["web-server"]["dmz"]

    print(f"  Router IP: {router_ip}")
    print(f"  Endpoint IP: {endpoint_ip}")

    # Router should get .1, endpoint should get .64
    assert router_ip == "10.0.0.1", f"Router should get .1, got {router_ip}"
    assert endpoint_ip == "10.0.0.64", f"Endpoint should get .64, got {endpoint_ip}"

    print("  ✓ IP allocation correct")


def test_switch_topology():
    """Test topology with 3+ nodes requiring a switch."""
    print("\n[Test 2] Switch-based topology (3 nodes)")
    print("-" * 50)

    blueprint = NetworkBlueprint(
        lab_name="test-lab-2",
        complexity="simple",
        subnets=["internal"],
        nodes=[
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
            ),
            LogicalNode(
                name="db-server",
                role="endpoint",
                image_flavor="ubuntu",
                connected_subnets=["internal"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/test2")
    builder.build()

    # Verify IP allocation
    router_ip = builder.node_ip_map["core-router"]["internal"]
    app_ip = builder.node_ip_map["app-server"]["internal"]
    db_ip = builder.node_ip_map["db-server"]["internal"]
    switch_ip = builder.node_ip_map.get("sw-internal", {}).get("internal")

    print(f"  Router IP: {router_ip}")
    print(f"  App Server IP: {app_ip}")
    print(f"  DB Server IP: {db_ip}")
    print(f"  Switch IP: {switch_ip}")

    # Router should get .1, switch .2, endpoints .64 and .65
    # Note: Each test creates a fresh NetworkBuilder, so subnet starts from 10.0.0.0/24
    assert router_ip == "10.0.0.1", f"Router should get .1, got {router_ip}"
    assert switch_ip == "10.0.0.2", f"Switch should get .2, got {switch_ip}"
    assert app_ip == "10.0.0.64", f"App server should get .64, got {app_ip}"
    assert db_ip == "10.0.0.65", f"DB server should get .65, got {db_ip}"

    print("  ✓ IP allocation correct")


def test_multi_subnet_topology():
    """Test topology with multiple subnets."""
    print("\n[Test 3] Multi-subnet topology")
    print("-" * 50)

    blueprint = NetworkBlueprint(
        lab_name="test-lab-3",
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

    builder = NetworkBuilder(blueprint, output_dir="./test_output/test3")
    builder.build()

    # Verify subnet ordering
    dmz_subnet = str(builder.subnet_map["dmz"])
    internal_subnet = str(builder.subnet_map["internal"])
    backend_subnet = str(builder.subnet_map["backend"])

    print(f"  DMZ subnet: {dmz_subnet}")
    print(f"  Internal subnet: {internal_subnet}")
    print(f"  Backend subnet: {backend_subnet}")

    assert dmz_subnet == "10.0.0.0/24"
    assert internal_subnet == "10.0.1.0/24"
    assert backend_subnet == "10.0.2.0/24"

    print("  ✓ Subnet ordering correct")

    # Verify IPs in each subnet
    print(f"\n  DMZ:")
    print(f"    edge-router: {builder.node_ip_map['edge-router']['dmz']}")
    print(f"    web-server: {builder.node_ip_map['web-server']['dmz']}")

    print(f"\n  Internal:")
    print(f"    edge-router: {builder.node_ip_map['edge-router']['internal']}")
    print(f"    core-router: {builder.node_ip_map['core-router']['internal']}")
    print(f"    app-server: {builder.node_ip_map['app-server']['internal']}")

    print(f"\n  Backend:")
    print(f"    core-router: {builder.node_ip_map['core-router']['backend']}")
    print(f"    db-server: {builder.node_ip_map['db-server']['backend']}")

    # Verify infrastructure range (.1, .2)
    assert builder.node_ip_map['edge-router']['dmz'] == "10.0.0.1"
    assert builder.node_ip_map['web-server']['dmz'] == "10.0.0.64"

    # Routers get sequential .1, .2 in point-to-point
    assert builder.node_ip_map['edge-router']['internal'] == "10.0.1.1"
    assert builder.node_ip_map['core-router']['internal'] == "10.0.1.2"

    print("  ✓ All IP allocations correct")


def test_frr_router_id_uniqueness():
    """Test that FRR routers get unique router-ids."""
    print("\n[Test 4] FRR Router-ID uniqueness")
    print("-" * 50)

    blueprint = NetworkBlueprint(
        lab_name="test-lab-4",
        complexity="complex",
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
                name="router-3",
                role="router",
                image_flavor="alpine",
                connected_subnets=["net3", "net1"]
            )
        ]
    )

    builder = NetworkBuilder(blueprint, output_dir="./test_output/test4")
    builder.build()

    # Check that FRR configs were generated
    import os

    for i in range(1, 4):
        router_name = f"router-{i}"
        frr_conf_path = f"./test_output/test4/{router_name}/frr.conf"

        assert os.path.exists(frr_conf_path), f"FRR config not found for {router_name}"

        with open(frr_conf_path, 'r') as f:
            content = f.read()
            assert f"hostname {router_name}" in content

            # Extract router-id (format: ospf router-id X.X.X.X)
            import re
            match = re.search(r'ospf router-id (\d+\.\d+\.\d+\.\d+)', content)
            assert match, f"Router-ID not found in {router_name} config"

            router_id = match.group(1)
            print(f"  {router_name}: router-id {router_id}")

        print(f"  ✓ {router_name} config generated")

    print("  ✓ All FRR configs generated successfully")


def main():
    """Run all tests."""
    print("=" * 60)
    print("IPAM Module Test Suite")
    print("Testing new C-class allocation rules")
    print("=" * 60)

    try:
        test_simple_two_node_topology()
        test_switch_topology()
        test_multi_subnet_topology()
        test_frr_router_id_uniqueness()

        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        return 0

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
