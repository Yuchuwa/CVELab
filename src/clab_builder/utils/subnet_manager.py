#!/usr/bin/env python3
"""子网管理工具 - 自动检测和分配可用子网"""

import subprocess
import ipaddress
from typing import List, Optional

class SubnetManager:
    """子网管理器"""

    def __init__(self):
        self.existing_networks = self._get_existing_docker_networks()

    def _get_existing_docker_networks(self) -> List[str]:
        """获取现有Docker网络"""
        networks = []

        try:
            result = subprocess.run(
                ['docker', 'network', 'ls', '--format', '{{{{.Subnet}}}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.strip().split('\n'):
                if line and line != '<none>' and ':' not in line:
                    networks.append(line)

        except Exception as e:
            print(f"获取Docker网络列表失败: {e}")

        return networks

    def find_available_subnet(self, preferred_ranges: List[str] = None) -> Optional[str]:
        """
        查找可用的子网

        Args:
            preferred_ranges: 优先使用的子网范围列表

        Returns:
            可用的子网CIDR，如果没有找到返回None
        """
        if preferred_ranges is None:
            # 默认优先级：10.x, 172.16-31.x, 192.168.x
            preferred_ranges = [
                "10.0.0.0/8",           # 10.0.0.0 - 10.255.255.255
                "172.16.0.0/12",        # 172.16.0.0 - 172.31.255.255
                "192.168.0.0/16"        # 192.168.0.0 - 192.168.255.255
            ]

        # 检查每个优先范围
        for base_cidr in preferred_ranges:
            available_subnet = self._find_subnet_in_range(base_cidr)
            if available_subnet:
                return available_subnet

        # 如果优先范围都不可用，尝试其他范围
        alternative_ranges = [
            "172.32.0.0/12",        # 172.32.0.0 - 172.47.255.255
            "172.48.0.0/12",        # 172.48.0.0 - 172.63.255.255
            "172.64.0.0/10",        # 172.64.0.0 - 172.127.255.255
            "172.128.0.0/9"         # 172.128.0.0 - 172.255.255.255
        ]

        for base_cidr in alternative_ranges:
            available_subnet = self._find_subnet_in_range(base_cidr)
            if available_subnet:
                return available_subnet

        return None

    def _find_subnet_in_range(self, base_cidr: str, subnet_size: int = 24) -> Optional[str]:
        """
        在指定范围内查找可用的/24子网

        Args:
            base_cidr: 基础网络范围（如 "10.0.0.0/8"）
            subnet_size: 子网大小（默认/24）

        Returns:
            可用的子网CIDR，如果找不到返回None
        """
        try:
            base_network = ipaddress.ip_network(base_cidr)
            existing_nets = []

            # 将现有网络转换为ipaddress对象
            for existing_cidr in self.existing_networks:
                try:
                    # 处理不同长度的CIDR
                    if '/' not in existing_cidr:
                        existing_cidr += '/16'  # 默认假设/16
                    existing_nets.append(ipaddress.ip_network(existing_cidr, strict=False))
                except:
                    continue

            # 尝试在基础网络中找到不重叠的子网
            subnets = list(base_network.subnets(new_prefix=subnet_size))

            for subnet in subnets:
                overlap_found = False

                for existing_net in existing_nets:
                    try:
                        if subnet.overlaps(existing_net):
                            overlap_found = True
                            break
                    except:
                        continue

                if not overlap_found:
                    return str(subnet)

        except Exception as e:
            print(f"子网查找异常: {e}")

        return None

    def get_network_conflicts(self, target_subnet: str) -> List[str]:
        """
        检查特定子网的冲突情况

        Args:
            target_subnet: 要检查的目标子网

        Returns:
            与目标子网冲突的网络列表
        """
        conflicts = []

        try:
            target_net = ipaddress.ip_network(target_subnet)

            for existing_cidr in self.existing_networks:
                try:
                    if '/' not in existing_cidr:
                        existing_cidr += '/16'
                    existing_net = ipaddress.ip_network(existing_cidr, strict=False)

                    if target_net.overlaps(existing_net):
                        conflicts.append(existing_cidr)

                except:
                    continue

        except Exception as e:
            print(f"冲突检测异常: {e}")

        return conflicts

    def suggest_subnet_cleanup(self) -> List[dict]:
        """
        建议需要清理的Docker网络

        Returns:
            建议清理的网络列表
        """
        suggestions = []

        try:
            result = subprocess.run(
                ['docker', 'network', 'ls', '--format', '{{{{.Name}}}\t{{{{.Subnet}}}}\t{{{{.Driver}}}}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        name, subnet = parts[0], parts[1]

                        # 建议清理的判断条件
                        should_cleanup = False
                        reason = []

                        if 'xben' in name.lower() or 'test' in name.lower():
                            should_cleanup = True
                            reason.append("测试网络")

                        if subnet.startswith('172.20.') or subnet.startswith('172.21.'):
                            should_cleanup = True
                            reason.append("可能与ContainerLab默认子网冲突")

                        if parts[2] == 'bridge':
                            should_cleanup = False  # 保留bridge网络

                        if should_cleanup:
                            suggestions.append({
                                'name': name,
                                'subnet': subnet,
                                'reason': ', '.join(reason)
                            })

        except Exception as e:
            print(f"生成清理建议失败: {e}")

        return suggestions


def main():
    """测试子网管理功能"""
    manager = SubnetManager()

    print("🔍 当前Docker网络:")
    for net in manager.existing_networks:
        print(f"   - {net}")

    print("\n📊 查找可用子网:")
    available_subnet = manager.find_available_subnet()
    if available_subnet:
        print(f"   ✅ 找到可用子网: {available_subnet}")
    else:
        print(f"   ❌ 未找到可用子网")

    print("\n⚠️  建议清理的网络:")
    suggestions = manager.suggest_subnet_cleanup()
    for suggestion in suggestions:
        print(f"   - {suggestion['name']} ({suggestion['subnet']}): {suggestion['reason']}")


if __name__ == "__main__":
    main()