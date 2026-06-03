#!/usr/bin/env python3
"""
测试CVE Catalog加载器功能
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from clab_builder.atomic.catalog import CVECatalogLoader


def test_catalog_loader():
    """测试catalog加载器"""
    print("🔍 测试CVE Catalog加载器")
    print("=" * 40)

    # 创建加载器
    loader = CVECatalogLoader("data/catalogs/verified")

    # 加载所有catalogs
    print("📁 加载所有验证过的catalogs...")
    catalogs = loader.load_all_catalogs()

    if not catalogs:
        print("❌ 没有找到catalog文件")
        return

    print(f"✅ 成功加载 {len(catalogs)} 个CVE catalog:")

    # 显示每个catalog的基本信息
    for cve_id, catalog in catalogs.items():
        print(f"\n🎯 {cve_id}:")
        print(f"   名称: {catalog.basic_info.name}")
        print(f"   CVSS: {catalog.basic_info.cvss_score}")
        print(f"   主要阶段: {catalog.get_primary_attack_stage()}")
        print(f"   拓扑适配: {catalog.topology_fit.network_layer.value}")
        print(f"   网络层: {catalog.topology_fit.network_layer.value}")
        print(f"   复杂度: {catalog.get_complexity_level()}")
        print(f"   已验证: {catalog.is_verified()}")

    # 测试按阶段查询
    print(f"\n🎯 查询适合 'initial_access' 阶段的CVE:")
    initial_access_cves = loader.get_cves_by_stage("initial_access", 0.7)

    for catalog in initial_access_cves:
        print(f"   - {catalog.basic_info.cve_id}: {catalog.basic_info.name}")

    # 测试按复杂度查询
    print(f"\n🎯 查询复杂度 <= 'medium' 的CVE:")
    simple_cves = loader.get_cves_by_complexity("medium")

    for catalog in simple_cves:
        print(f"   - {catalog.basic_info.cve_id}: {catalog.get_complexity_level()}")

    # 显示转换示例
    print(f"\n🔧 Catalog转换示例:")
    if catalogs:
        first_catalog = list(catalogs.values())[0]
        dict_form = first_catalog.to_dict()
        print(f"   CVE: {dict_form['cve_id']}")
        print(f"   镜像: {dict_form['docker_image']}")
        print(f"   主要阶段: {dict_form['primary_stage']}")
        print(f"   网络层: {dict_form['network_layer']}")

    print(f"\n" + "=" * 40)
    print("🎉 Catalog加载器测试完成！")


if __name__ == "__main__":
    test_catalog_loader()