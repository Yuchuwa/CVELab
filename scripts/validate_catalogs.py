#!/usr/bin/env python3
"""
CVE Catalog验证工具 - 验证所有catalog的完整性和准确性

这是CI/CD流水线中验证CVE catalog的关键工具
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import yaml
import glob
from pathlib import Path

from clab_builder.atomic.validator import CVEAtomicValidator, CVEQualityScorer


def validate_all_catalogs(catalog_dir: str = "data/catalogs/verified"):
    """验证所有catalog文件"""
    print(f"🔍 验证目录: {catalog_dir}")

    catalog_files = glob.glob(os.path.join(catalog_dir, "*.yaml"))

    if not catalog_files:
        print("❌ 没有找到catalog文件")
        return False

    print(f"📁 找到 {len(catalog_files)} 个catalog文件")

    validator = CVEAtomicValidator()
    scorer = CVEQualityScorer()

    total_catalogs = len(catalog_files)
    valid_catalogs = 0
    high_quality_catalogs = 0

    validation_results = []

    for catalog_file in catalog_files:
        cve_id = os.path.basename(catalog_file).replace('.yaml', '')
        print(f"\n🔍 验证 {cve_id}:")

        try:
            with open(catalog_file, 'r') as f:
                catalog_data = yaml.safe_load(f)

            # 执行各种验证
            syntax_valid, syntax_issues = validator.validate_catalog_syntax(catalog_data)
            logic_valid, logic_issues = validator.validate_logic_consistency(catalog_data)
            exploit_valid, exploit_issues = validator.validate_exploit_possibility(catalog_data)

            all_issues = syntax_issues + logic_issues + exploit_issues

            # 质量评分
            quality_score = scorer.score_catalog(catalog_data)

            is_valid = all([syntax_valid, logic_valid, exploit_valid])
            is_high_quality = quality_score['total_score'] >= 0.8

            if is_valid:
                valid_catalogs += 1
                if is_high_quality:
                    high_quality_catalogs += 1

            # 记录结果
            validation_results.append({
                'cve_id': cve_id,
                'valid': is_valid,
                'high_quality': is_high_quality,
                'quality_score': quality_score['total_score'],
                'issues': all_issues
            })

            # 显示结果
            status_icon = "✅" if is_valid else "❌"
            quality_icon = "⭐" if is_high_quality else "📊"

            print(f"   {status_icon} 语法验证: {'通过' if syntax_valid else '失败'}")
            print(f"   {status_icon} 逻辑验证: {'通过' if logic_valid else '失败'}")
            print(f"   {status_icon} 利用验证: {'通过' if exploit_valid else '失败'}")
            print(f"   {quality_icon} 质量总分: {quality_score['total_score']:.2f}")

            if all_issues:
                print(f"   ⚠️  问题:")
                for issue in all_issues[:3]:  # 只显示前3个问题
                    print(f"      - {issue}")

        except Exception as e:
            print(f"   ❌ 验证失败: {e}")
            validation_results.append({
                'cve_id': cve_id,
                'valid': False,
                'high_quality': False,
                'quality_score': 0.0,
                'issues': [str(e)]
            })

    # 输出汇总
    print(f"\n" + "=" * 50)
    print("📊 验证汇总:")
    print(f"   总catalog数: {total_catalogs}")
    print(f"   有效catalog: {valid_catalogs} ({valid_catalogs/total_catalogs*100:.1f}%)")
    print(f"   高质量catalog: {high_quality_catalogs} ({high_quality_catalogs/total_catalogs*100:.1f}%)")

    # 计算平均质量分数
    if validation_results:
        avg_quality = sum(r['quality_score'] for r in validation_results) / len(validation_results)
        print(f"   平均质量分数: {avg_quality:.2f}")

    return valid_catalogs == total_catalogs


def check_catalog_consistency():
    """检查catalog之间的一致性"""
    print("🔍 检查catalog一致性")

    catalog_dir = "data/catalogs/verified"
    loader = CVECatalogLoader(catalog_dir)

    # 加载所有catalogs
    catalogs = loader.load_all_catalogs()

    if not catalogs:
        print("❌ 没有可用的catalog")
        return False

    # 检查1: CVE ID格式一致性
    cve_id_issues = []
    for cve_id in catalogs.keys():
        if not cve_id.startswith('CVE-'):
            cve_id_issues.append(f"Invalid CVE ID format: {cve_id}")

    if cve_id_issues:
        print("❌ CVE ID格式问题:")
        for issue in cve_id_issues:
            print(f"   - {issue}")

    # 检查2: 端口冲突
    port_usage = {}
    for catalog in catalogs.values():
        for port in catalog.environment.required_ports:
            if port not in port_usage:
                port_usage[port] = []
            port_usage[port].append(catalog.basic_info.cve_id)

    port_conflicts = []
    for port, cve_list in port_usage.items():
        if len(cve_list) > 1:
            port_conflicts.append(f"Port {port} used by multiple CVEs: {', '.join(cve_list)}")

    if port_conflicts:
        print("⚠️  端口冲突:")
        for conflict in port_conflicts:
            print(f"   - {conflict}")

    print(f"✅ 一致性检查完成")
    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='CVE Catalog验证工具')
    parser.add_argument('--directory', default='data/catalogs/verified',
                       help='catalog目录路径')
    parser.add_argument('--consistency', action='store_true',
                       help='检查catalog间一致性')

    args = parser.parse_args()

    if args.consistency:
        check_catalog_consistency()
    else:
        success = validate_all_catalogs(args.directory)
        sys.exit(0 if success else 1)