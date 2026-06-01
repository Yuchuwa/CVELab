#!/usr/bin/env python3
"""CVE集成测试 - 测试CVE exploit playbook生成功能"""

import pytest
import tempfile
import os
from clab_builder.core.generator import TopologyGenerator

# 创建测试YAML，包含CVE注入
test_yaml = """
name: cve-test-lab
topology:
  nodes:
    attacker1:
      kind: linux
      image: kalilinux/kali-rolling:latest
      labels:
        role: attacker

    victim1:
      kind: linux
      image: vulhub/log4j:latest
      labels:
        role: victim
        cve_id: CVE-2021-44228
        cve_name: Apache Log4j RCE
        cvss_score: 10.0

    router1:
      kind: linux
      image: alpine:latest
      labels:
        role: router

  links:
    - endpoints: ["attacker1:eth1", "router1:eth1"]
    - endpoints: ["victim1:eth1", "router1:eth2"]
"""

@pytest.mark.integration
@pytest.mark.cve
def test_cve_exploit_playbook_generation():
    """测试CVE exploit playbook生成功能"""
    # 创建临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(test_yaml)
        test_file = f.name

    try:
        # 创建生成器
        generator = TopologyGenerator(test_file)

        # 生成配置
        clab_config, ansible_config = generator.generate()

        # 验证基本配置生成
        assert clab_config is not None
        assert ansible_config is not None

        # 检查playbooks生成
        playbooks = ansible_config.get('playbooks', {})
        assert 'cve_exploits' in playbooks, "CVE exploit playbooks应该被生成"

        # 验证CVE exploit playbook内容
        cve_playbooks = playbooks['cve_exploits']
        assert len(cve_playbooks) > 0, "应该至少生成一个CVE exploit playbook"

        # 检查Log4j exploit playbook
        log4j_playbook_found = False
        for name, content in cve_playbooks.items():
            if 'CVE_2021_44228' in name:
                log4j_playbook_found = True
                assert 'Log4j CVE-2021-44228 Exploit Playbook' in content
                assert 'environment preparation' in content.lower() or '环境准备' in content
                assert 'exploit' in content.lower() or '攻击' in content
                break

        assert log4j_playbook_found, "应该找到Log4j exploit playbook"

    finally:
        # 清理临时文件
        if os.path.exists(test_file):
            os.unlink(test_file)


def main():
    """独立运行此测试的入口点"""
    print("🧪 测试CVE exploit playbook生成功能")
    print("=" * 50)

    # 写入临时文件
    test_file = "/tmp/test_cve_topology.yaml"
    with open(test_file, 'w') as f:
        f.write(test_yaml)

    # 创建生成器
    generator = TopologyGenerator(test_file)

    # 生成配置
    clab_config, ansible_config = generator.generate()

    print("\n📋 ContainerLab配置生成完成")
    print("📋 Ansible配置生成完成")

    # 检查CVE exploit playbooks是否生成
    playbooks = ansible_config.get('playbooks', {})
    print(f"\n🎯 生成的Playbooks: {list(playbooks.keys())}")

    if 'cve_exploits' in playbooks:
        print("✅ CVE exploit playbooks生成成功!")
        cve_playbooks = playbooks['cve_exploits']
        print(f"   CVE Playbook数量: {len(cve_playbooks)}")

        for name, content in cve_playbooks.items():
            print(f"   - {name}")
            print(f"     内容预览: {content[:200]}...")
    else:
        print("❌ CVE exploit playbooks未生成")

    print("\n" + "=" * 50)
    print("🎉 CVE集成测试完成!")

if __name__ == "__main__":
    main()