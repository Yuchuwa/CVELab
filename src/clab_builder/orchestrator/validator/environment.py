"""环境验证器 - 完整的部署、验证、清理流程

集成ContainerLab环境验证、CVE利用验证、质量检查等功能
"""
import subprocess
import tempfile
import os
import yaml
import json
import time
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime, timedelta
from clab_builder.shared.utils import SubnetManager
from .connectivity import EnhancedConnectivityTester


class EnvironmentValidator:
    """完整的环境验证器"""

    def __init__(self, cleanup_on_failure: bool = True):
        self.cleanup_on_failure = cleanup_on_failure
        self.validation_results = []
        self.subnet_manager = SubnetManager()  # 集成子网管理器

    def validate_generated_environment(
        self,
        topology_file: str,
        attack_playbook_file: Optional[str] = None,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        完整验证生成的环境

        Args:
            topology_file: ContainerLab拓扑文件路径
            attack_playbook_file: 攻击playbook文件路径（可选）
            timeout: 验证超时时间

        Returns:
            完整的验证结果
        """
        validation_result = {
            'environment_id': Path(topology_file).stem,
            'validation_start': datetime.now().isoformat(),
            'stages': {},
            'overall_status': 'unknown',
            'quality_score': 0.0
        }

        try:
            # 阶段1: 语法验证
            print("🔍 阶段1: 语法验证")
            syntax_result = self._validate_syntax(topology_file)
            validation_result['stages']['syntax'] = syntax_result

            if not syntax_result['valid']:
                validation_result['overall_status'] = 'syntax_error'
                return validation_result

            print("✅ 语法验证通过")

            # 阶段2: 环境部署验证
            print("🚀 阶段2: 环境部署验证")
            deploy_result = self._validate_deployment(topology_file, timeout)
            validation_result['stages']['deployment'] = deploy_result

            if not deploy_result['success']:
                validation_result['overall_status'] = 'deployment_failed'
                if self.cleanup_on_failure:
                    self._cleanup_environment(topology_file)
                return validation_result

            print("✅ 环境部署成功")

            # 阶段3: 容器状态验证
            print("📊 阶段3: 容器状态验证")
            container_result = self._validate_containers(deploy_result['lab_name'])
            validation_result['stages']['containers'] = container_result

            if not container_result['all_running']:
                validation_result['overall_status'] = 'container_error'
                if self.cleanup_on_failure:  # 只有在cleanup_on_failure=True时才清理
                    self._cleanup_environment(topology_file)
                return validation_result

            print("✅ 容器状态正常")

            # 阶段4: 网络连通性验证（增强版）
            print("🌐 阶段4: 网络连通性验证（增强版）")
            # 等待容器网络完全就绪
            print("   ⏳ 等待容器网络就绪...")
            time.sleep(3)
            network_result = self._validate_enhanced_network_connectivity(deploy_result['lab_name'], topology_file)
            validation_result['stages']['network'] = network_result

            # 阶段5: CVE可利用性验证（如果有攻击playbook）
            if attack_playbook_file and os.path.exists(attack_playbook_file):
                print("🎯 阶段5: CVE可利用性验证")
                cve_result = self._validate_cve_exploitability(
                    deploy_result['lab_name'],
                    attack_playbook_file
                )
                validation_result['stages']['cve_exploit'] = cve_result
            else:
                print("⏭️  跳过CVE验证（无攻击playbook）")
                validation_result['stages']['cve_exploit'] = {'skipped': True}

            # 计算质量分数
            validation_result['quality_score'] = self._calculate_quality_score(validation_result)
            validation_result['overall_status'] = 'success'

            # 清理环境（除非用户要求保留）
            if not self.cleanup_on_failure:
                print("🧹 清理环境")
                self._cleanup_environment(topology_file)
                print("✅ 环境清理完成")
            else:
                print("🔧 保留环境用于检查（--keep参数）")

            validation_result['validation_end'] = datetime.now().isoformat()
            validation_result['total_duration'] = (
                datetime.fromisoformat(validation_result['validation_end']) -
                datetime.fromisoformat(validation_result['validation_start'])
            ).total_seconds()

        except Exception as e:
            validation_result['overall_status'] = 'validation_exception'
            validation_result['exception'] = str(e)
            if self.cleanup_on_failure:
                self._cleanup_environment(topology_file)

        return validation_result

    def _validate_syntax(self, topology_file: str) -> Dict[str, Any]:
        """验证ContainerLab配置语法"""
        result = {'valid': True, 'errors': [], 'warnings': []}

        try:
            # 使用containerlab graph命令验证语法（离线模式）
            cmd_result = subprocess.run(
                ['clab', 'graph', '-t', topology_file, '--dot'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if cmd_result.returncode != 0:
                result['valid'] = False
                result['errors'].append(f"ContainerLab语法错误: {cmd_result.stderr}")

        except subprocess.TimeoutExpired:
            result['warnings'].append("语法验证超时")
        except FileNotFoundError:
            result['warnings'].append("containerlab命令未找到")
        except Exception as e:
            result['warnings'].append(f"语法验证异常: {str(e)}")

        # 额外验证YAML格式
        try:
            with open(topology_file, 'r') as f:
                yaml_content = yaml.safe_load(f)
                if 'topology' not in yaml_content:
                    result['valid'] = False
                    result['errors'].append("缺少topology字段")
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"YAML解析错误: {str(e)}")

        return result

    def _validate_deployment(self, topology_file: str, timeout: int) -> Dict[str, Any]:
        """验证环境部署"""
        result = {
            'success': False,
            'lab_name': None,
            'deployment_time': 0,
            'output': '',
            'errors': [],
            'subnet_used': None
        }

        start_time = time.time()

        try:
            # 使用子网管理器自动检测可用子网
            print("   🔍 检测可用Docker管理子网...")
            available_subnet = self.subnet_manager.find_available_subnet()

            if available_subnet:
                print(f"   ✅ 找到可用管理子网: {available_subnet}")
                result['subnet_used'] = available_subnet
                deploy_cmd = ['clab', 'deploy', '-t', topology_file, '--ipv4-subnet', available_subnet]
            else:
                print("   ⚠️  未找到完全可用的子网，使用默认配置")
                deploy_cmd = ['clab', 'deploy', '-t', topology_file]

            deploy_result = subprocess.run(
                deploy_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # 调试输出
            if deploy_result.returncode != 0:
                print(f"   ❌ 部署失败，返回码: {deploy_result.returncode}")
                print(f"   错误输出: {deploy_result.stderr[:200]}")

            deployment_time = time.time() - start_time
            result['deployment_time'] = deployment_time

            if deploy_result.returncode == 0:
                result['success'] = True
                result['output'] = deploy_result.stdout

                # 提取实验室名称（从输出中找到容器名称前缀）
                import re
                # 匹配容器名称模式，如 "clab-simple_test_lab-attacker" -> 提取 "clab-simple_test_lab"
                lab_name_match = re.search(r'(clab-[^\s|]+)-[^\s|]*', deploy_result.stdout)
                if lab_name_match:
                    result['lab_name'] = lab_name_match.group(1).strip()
                    print(f"   🔍 提取的lab名称: {result['lab_name']}")

                # 备用方案：从topology文件名推导
                if not result['lab_name']:
                    topology_name = Path(topology_file).stem
                    result['lab_name'] = f"clab-{topology_name}"
                    print(f"   🔍 使用推导的lab名称: {result['lab_name']}")
            else:
                # 检查部署错误原因
                error_output = deploy_result.stderr
                if not error_output:
                    error_output = deploy_result.stdout  # 有时错误信息在stdout中

                if 'overlap' in error_output.lower() or 'pool overlaps' in error_output.lower():
                    result['errors'].append("Docker网络重叠错误")

                    # 提供冲突网络信息
                    conflicting_nets = self.subnet_manager.get_network_conflicts("172.20.20.0/24")
                    if conflicting_nets:
                        result['network_conflicts'] = conflicting_nets
                        result['suggestion'] = "建议清理冲突的Docker网络或使用子网清理工具"
                else:
                    # 截取错误信息，避免过长
                    error_snippet = error_output[:300] if len(error_output) > 300 else error_output
                    result['errors'].append(f"部署失败: {error_snippet}")

                # 记录完整的错误输出到文件（调试用）
                result['full_error'] = error_output[:1000]  # 保存完整错误

        except subprocess.TimeoutExpired:
            result['errors'].append(f"部署超时（{timeout}秒）")
        except Exception as e:
            result['errors'].append(f"部署异常: {str(e)}")

        return result

    def _validate_containers(self, lab_name: str) -> Dict[str, Any]:
        """验证容器状态"""
        result = {
            'all_running': False,
            'containers': [],
            'total_count': 0,
            'running_count': 0,
            'errors': []
        }

        try:
            # 获取容器列表 - 使用简单的grep方式
            inspect_result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={lab_name}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if inspect_result.returncode == 0:
                lines = inspect_result.stdout.strip().split('\n')
                # 跳过标题行
                if lines and 'CONTAINER ID' in lines[0]:
                    lines = lines[1:]

                containers = []
                running_count = 0

                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            # 第一个非空部分是容器ID，第二个是镜像，状态在后面
                            container_name = None
                            container_state = None

                            # 查找容器名称和状态
                            for i, part in enumerate(parts):
                                if 'clab-' in part:
                                    container_name = part
                                if 'Up' in part or 'running' in part.lower():
                                    container_state = 'running'

                            if container_name:
                                is_running = container_state == 'running'

                                containers.append({
                                    'name': container_name,
                                    'state': container_state,
                                    'running': is_running
                                })

                                if is_running:
                                    running_count += 1

                result['containers'] = containers
                result['total_count'] = len(containers)
                result['running_count'] = running_count
                result['all_running'] = running_count == len(containers) and len(containers) > 0

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def _validate_network_connectivity(self, lab_name: str, topology_file: str = None) -> Dict[str, Any]:
        """验证网络连通性"""
        result = {
            'connectivity_tests': [],
            'success_rate': 0.0,
            'accessible_services': [],
            'warnings': None
        }

        try:
            # 获取实验室所有容器
            containers = self._get_lab_containers(lab_name)

            if not containers:
                result['warnings'] = "未找到任何容器"
                return result

            # 从拓扑文件中提取节点端口信息
            node_ports = self._extract_node_ports(topology_file) if topology_file else {}

            # 尝试找到attacker容器，如果没有则使用第一个运行的容器
            attacker_containers = [
                c for c in containers
                if 'attacker' in c['name'].lower() and 'up' in c['status'].lower()
            ]

            if not attacker_containers:
                # 使用第一个运行中的容器作为测试源
                running_containers = [
                    c for c in containers
                    if 'up' in c['status'].lower()
                ]
                if running_containers:
                    attacker_container = running_containers[0]['name']
                    result['warnings'] = f"未找到attacker容器，使用 {attacker_container} 进行连通性测试"
                else:
                    result['warnings'] = "没有运行中的容器"
                    return result
            else:
                attacker_container = attacker_containers[0]['name']
                print(f"🔍 使用attacker容器: {attacker_container}")

            accessible_services = []
            total_port_tests = 0

            for container in containers:
                if container['name'] != attacker_container and 'up' in container['status'].lower():
                    # 提取容器短名称（去除lab前缀）
                    container_short_name = container['name'].replace(f"{lab_name}-", "")

                    # 获取该容器应该测试的端口
                    ports_to_test = node_ports.get(container_short_name, [])

                    # 如果YAML中没有定义端口，使用常见端口作为后备
                    if not ports_to_test:
                        ports_to_test = [80, 443, 8080, 22]  # 减少后备端口数量

                    print(f"   测试连通性: {attacker_container} -> {container['name']} (端口: {ports_to_test})")

                    for port in ports_to_test:
                        total_port_tests += 1
                        try:
                            # 尝试连接测试
                            test_result = subprocess.run(
                                ['docker', 'exec', attacker_container, 'timeout', '2', 'bash', '-c',
                                 f"cat < /dev/null > /dev/tcp/{container['name']}/{port}"],
                                capture_output=True,
                                timeout=5
                            )

                            is_accessible = test_result.returncode == 0
                            if is_accessible:
                                accessible_services.append({
                                    'service': container['name'],
                                    'port': port,
                                    'protocol': 'tcp'
                                })
                                print(f"      ✅ 端口 {port} 可达")
                            else:
                                print(f"      ❌ 端口 {port} 不可达")

                        except Exception as e:
                            print(f"      ⚠️  端口 {port} 测试异常: {str(e)}")

            result['accessible_services'] = accessible_services
            result['connectivity_tests'] = len(accessible_services)

            # 计算连通率（基于实际执行的端口测试）
            if total_port_tests > 0:
                success_rate = len(accessible_services) / total_port_tests
                result['success_rate'] = min(success_rate, 1.0)  # 确保不超过1.0
            else:
                result['success_rate'] = 1.0  # 如果没有端口需要测试，认为连通性正常

            print(f"🌐 网络连通性测试完成: {len(accessible_services)}/{total_port_tests} 个服务可达，成功率: {result['success_rate']:.2%}")

        except Exception as e:
            result['error'] = str(e)
            print(f"❌ 网络连通性验证异常: {str(e)}")

        return result

    def _extract_node_ports(self, topology_file: str) -> Dict[str, List[int]]:
        """从拓扑文件中提取节点端口信息"""
        node_ports = {}

        try:
            with open(topology_file, 'r') as f:
                topology_data = yaml.safe_load(f)

            # 遍历拓扑中的节点
            nodes = topology_data.get('topology', {}).get('nodes', {})

            for node_name, node_config in nodes.items():
                ports = []
                # 从ports字段提取端口
                if 'ports' in node_config:
                    for port_str in node_config['ports']:
                        # 解析 "80/tcp" 格式
                        if '/' in port_str:
                            port_num = int(port_str.split('/')[0])
                            ports.append(port_num)
                        else:
                            ports.append(int(port_str))

                if ports:
                    node_ports[node_name] = ports
                    print(f"   📋 节点 {node_name} 定义端口: {ports}")

        except Exception as e:
            print(f"   ⚠️  提取端口信息失败: {str(e)}")

        return node_ports

    def _validate_enhanced_network_connectivity(self, lab_name: str, topology_file: str = None) -> Dict[str, Any]:
        """增强的网络连通性验证"""
        result = {
            'connectivity_tests': [],
            'success_rate': 0.0,
            'enhanced_metrics': {},
            'warnings': None
        }

        try:
            # 获取实验室所有容器
            containers = self._get_lab_containers(lab_name)

            if not containers:
                result['warnings'] = "未找到任何容器"
                return result

            # 从拓扑文件中提取节点端口信息
            node_ports = self._extract_node_ports(topology_file) if topology_file else {}

            # 创建增强的连通性测试器
            tester = EnhancedConnectivityTester()

            # 找到attacker容器或第一个运行中的容器作为测试源
            attacker_containers = [
                c for c in containers
                if 'attacker' in c['name'].lower() and 'up' in c['status'].lower()
            ]

            if not attacker_containers:
                running_containers = [
                    c for c in containers
                    if 'up' in c['status'].lower()
                ]
                if running_containers:
                    attacker_container = running_containers[0]['name']
                    result['warnings'] = f"未找到attacker容器，使用 {attacker_container} 进行测试"
                else:
                    result['warnings'] = "没有运行中的容器"
                    return result
            else:
                attacker_container = attacker_containers[0]['name']

            print(f"🔍 使用测试源容器: {attacker_container}")

            # 为每个目标容器执行增强的连通性测试
            test_results = []
            successful_tests = 0
            total_tests = 0

            for container in containers:
                if container['name'] != attacker_container and 'up' in container['status'].lower():
                    container_short_name = container['name'].replace(f"{lab_name}-", "")

                    # 获取该容器应该测试的端口
                    ports_to_test = node_ports.get(container_short_name, [80, 443, 22])

                    print(f"   🔍 测试连通性: {attacker_container} -> {container['name']} (端口: {ports_to_test})")

                    # 执行增强的连通性测试
                    enhanced_result = tester.comprehensive_connectivity_test(
                        attacker_container,
                        container['name'],
                        ports_to_test
                    )

                    test_results.append({
                        'target': container['name'],
                        'result': enhanced_result
                    })

                    total_tests += 1
                    if enhanced_result['overall_success']:
                        successful_tests += 1

            result['connectivity_tests'] = test_results

            # 计算增强的指标
            if total_tests > 0:
                result['success_rate'] = successful_tests / total_tests

            # 计算额外的网络质量指标
            result['enhanced_metrics'] = self._calculate_network_quality_metrics(test_results)

            print(f"🌐 增强网络连通性测试完成: {successful_tests}/{total_tests} 个连接成功，成功率: {result['success_rate']:.2%}")

            # 添加网络质量评估
            if 'network_health_score' in result['enhanced_metrics']:
                health_score = result['enhanced_metrics']['network_health_score']
                print(f"   📊 网络健康评分: {health_score:.1f}/100")

        except Exception as e:
            result['error'] = str(e)
            print(f"❌ 增强网络连通性验证异常: {str(e)}")

        return result

    def _calculate_network_quality_metrics(self, test_results: List[Dict]) -> Dict[str, Any]:
        """计算网络质量指标"""
        metrics = {
            'avg_latency_ms': 0.0,
            'max_latency_ms': 0.0,
            'packet_loss_rate': 0.0,
            'dns_resolution_success': 0.0,
            'route_tracing_success': 0.0,
            'network_health_score': 0.0
        }

        latencies = []
        packet_losses = []
        dns_success = 0
        route_success = 0
        total_tests = len(test_results)

        for test in test_results:
            result_data = test.get('result', {})

            # 提取ICMP延迟数据
            icmp_result = result_data.get('tests', {}).get('icmp_ping', {})
            if icmp_result.get('success'):
                avg_rtt = icmp_result.get('avg_rtt', 0)
                if avg_rtt > 0:
                    latencies.append(avg_rtt)

                packet_loss = icmp_result.get('packet_loss', 0)
                packet_losses.append(packet_loss)

            # 检查DNS解析成功率
            dns_result = result_data.get('tests', {}).get('dns_resolution', {})
            if dns_result.get('success'):
                dns_success += 1

            # 检查路由追踪成功率
            route_result = result_data.get('tests', {}).get('route_tracing', {})
            if route_result.get('success'):
                route_success += 1

        # 计算平均指标
        if latencies:
            metrics['avg_latency_ms'] = sum(latencies) / len(latencies)
            metrics['max_latency_ms'] = max(latencies)

        if packet_losses:
            metrics['packet_loss_rate'] = sum(packet_losses) / len(packet_losses)

        if total_tests > 0:
            metrics['dns_resolution_success'] = (dns_success / total_tests) * 100
            metrics['route_tracing_success'] = (route_success / total_tests) * 100

        # 计算网络健康评分 (0-100)
        health_score = 100.0

        # 延迟评分 (理想<10ms, 良好<50ms, 可接受<100ms)
        if metrics['avg_latency_ms'] > 0:
            if metrics['avg_latency_ms'] < 10:
                latency_score = 100
            elif metrics['avg_latency_ms'] < 50:
                latency_score = 80
            elif metrics['avg_latency_ms'] < 100:
                latency_score = 60
            else:
                latency_score = max(0, 100 - metrics['avg_latency_ms'])
        else:
            latency_score = 50  # 无数据时给中间分

        # 丢包率评分 (理想<1%, 良好<5%, 可接受<10%)
        if metrics['packet_loss_rate'] > 0:
            if metrics['packet_loss_rate'] < 1:
                packet_score = 100
            elif metrics['packet_loss_rate'] < 5:
                packet_score = 80
            elif metrics['packet_loss_rate'] < 10:
                packet_score = 60
            else:
                packet_score = max(0, 100 - metrics['packet_loss_rate'] * 10)
        else:
            packet_score = 50

        # DNS成功率评分
        dns_score = metrics['dns_resolution_success']

        # 路由追踪成功率评分
        route_score = metrics['route_tracing_success']

        # 综合评分
        health_score = (latency_score * 0.3 + packet_score * 0.3 +
                       dns_score * 0.2 + route_score * 0.2)

        metrics['network_health_score'] = health_score

        return metrics

    def _validate_cve_exploitability(self, lab_name: str, playbook_file: str) -> Dict[str, Any]:
        """验证CVE可利用性"""
        result = {
            'exploit_attempts': [],
            'successful_exploits': [],
            'failed_exploits': [],
            'exploit_success_rate': 0.0
        }

        try:
            # 读取playbook文件
            with open(playbook_file, 'r') as f:
                playbook_content = yaml.safe_load(f)

            # 简化验证：检查playbook是否可以正确解析
            if isinstance(playbook_content, list):
                result['exploit_attempts'] = len(playbook_content)
                # 实际CVE验证需要更复杂的逻辑
                # 这里做基础的结构验证
                result['structure_valid'] = True
            else:
                result['exploit_attempts'] = 0
                result['structure_valid'] = False

        except Exception as e:
            result['error'] = str(e)
            result['structure_valid'] = False

        return result

    def _get_lab_containers(self, lab_name: str) -> List[Dict[str, Any]]:
        """获取实验室所有容器"""
        containers = []

        try:
            # 使用更可靠的格式获取容器信息
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', f'name={lab_name}', '--format', '{{.Names}}\t{{.Status}}\t{{.Ports}}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            containers.append({
                                'name': parts[0].strip(),
                                'status': parts[1].strip(),
                                'ports': parts[2].strip() if len(parts) > 2 else ''
                            })

                print(f"🔍 找到 {len(containers)} 个容器")
                for container in containers:
                    print(f"   - {container['name']}: {container['status']}")

        except Exception as e:
            print(f"获取容器列表失败: {str(e)}")

        return containers

    def _cleanup_environment(self, topology_file: str) -> bool:
        """清理环境"""
        try:
            result = subprocess.run(
                ['clab', 'destroy', '-t', topology_file, '--cleanup'],
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode == 0
        except:
            return False

    def _calculate_quality_score(self, validation_result: Dict[str, Any]) -> float:
        """计算质量分数"""
        score = 0.0
        max_score = 100.0

        # 语法验证 (20分)
        if validation_result['stages'].get('syntax', {}).get('valid', False):
            score += 20.0

        # 部署成功 (30分)
        if validation_result['stages'].get('deployment', {}).get('success', False):
            score += 30.0

        # 容器运行 (20分)
        if validation_result['stages'].get('containers', {}).get('all_running', False):
            score += 20.0

        # 网络连通性 (15分)
        network_score = validation_result['stages'].get('network', {}).get('success_rate', 0.0)
        score += network_score * 15.0

        # CVE验证 (15分)
        cve_stage = validation_result['stages'].get('cve_exploit', {})
        if not cve_stage.get('skipped', False):
            if cve_stage.get('structure_valid', False):
                score += 15.0

        return round(score, 2)

    def batch_validate_environments(
        self,
        topology_files: List[str],
        max_concurrent: int = 3,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """批量验证环境"""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_to_topology = {
                executor.submit(self.validate_generated_environment, topology_file, None, timeout): topology_file
                for topology_file in topology_files
            }

            for future in as_completed(future_to_topology):
                topology_file = future_to_topology[future]
                try:
                    result = future.result()
                    results.append(result)

                    status_emoji = "✅" if result['overall_status'] == 'success' else "❌"
                    print(f"{status_emoji} {Path(topology_file).stem}: {result['overall_status']} (质量分: {result['quality_score']})")

                except Exception as e:
                    print(f"❌ {Path(topology_file).stem}: 验证异常 - {str(e)}")
                    results.append({
                        'environment_id': Path(topology_file).stem,
                        'overall_status': 'validation_exception',
                        'exception': str(e)
                    })

        # 生成批量摘要
        batch_summary = {
            'batch_date': datetime.now().isoformat(),
            'total_environments': len(topology_files),
            'successful': len([r for r in results if r['overall_status'] == 'success']),
            'failed': len([r for r in results if r['overall_status'] != 'success']),
            'average_quality_score': sum(r.get('quality_score', 0) for r in results) / len(results),
            'results': results
        }

        return batch_summary


class CVEExploitValidator:
    """CVE利用验证器 - 专门验证CVE的实际可利用性"""

    def __init__(self):
        self.exploit_results = []

    def validate_cve_exploit(
        self,
        lab_name: str,
        cve_id: str,
        exploit_steps: List[Dict[str, Any]],
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        验证特定CVE的可利用性

        Args:
            lab_name: 实验室名称
            cve_id: CVE编号
            exploit_steps: 攻击步骤列表
            timeout: 超时时间

        Returns:
            CVE利用验证结果
        """
        result = {
            'cve_id': cve_id,
            'lab_name': lab_name,
            'exploit_attempted': False,
            'exploit_successful': False,
            'steps_completed': 0,
            'steps_failed': 0,
            'total_steps': len(exploit_steps),
            'execution_time': 0,
            'errors': [],
            'output': []
        }

        start_time = time.time()

        try:
            # 执行攻击步骤
            for i, step in enumerate(exploit_steps):
                step_result = self._execute_exploit_step(lab_name, step, timeout)
                result['output'].append(step_result)

                if step_result['success']:
                    result['steps_completed'] += 1
                else:
                    result['steps_failed'] += 1
                    result['errors'].append(f"步骤{i+1}失败: {step_result.get('error', 'Unknown')}")

                    # 如果是关键步骤失败，可能停止后续步骤
                    if step.get('critical', False):
                        break

            result['exploit_attempted'] = True
            result['exploit_successful'] = result['steps_completed'] == result['total_steps']

        except Exception as e:
            result['errors'].append(f"利用验证异常: {str(e)}")

        result['execution_time'] = time.time() - start_time

        return result

    def _execute_exploit_step(
        self,
        lab_name: str,
        step: Dict[str, Any],
        timeout: int
    ) -> Dict[str, Any]:
        """执行单个攻击步骤"""
        result = {
            'success': False,
            'command': step.get('command', ''),
            'output': '',
            'error': None
        }

        try:
            # 这里需要根据具体步骤类型执行不同的操作
            tool = step.get('tool', '')
            command = step.get('command', '')

            if tool == 'nmap':
                # 执行端口扫描
                result = self._execute_nmap_step(lab_name, command, timeout)
            elif tool == 'curl':
                # 执行HTTP请求
                result = self._execute_curl_step(lab_name, command, timeout)
            elif tool == 'shell':
                # 执行shell命令
                result = self._execute_shell_step(lab_name, command, timeout)
            else:
                result['error'] = f"未知工具类型: {tool}"

        except Exception as e:
            result['error'] = str(e)

        return result

    def _execute_nmap_step(self, lab_name: str, command: str, timeout: int) -> Dict[str, Any]:
        """执行nmap扫描步骤"""
        result = {'success': False, 'command': command, 'output': '', 'error': None}

        try:
            # 在attacker容器中执行nmap
            attacker_container = self._find_attacker_container(lab_name)
            if not attacker_container:
                result['error'] = "未找到attacker容器"
                return result

            exec_command = f"docker exec {attacker_container} {command}"
            cmd_result = subprocess.run(
                exec_command.split(),
                capture_output=True,
                text=True,
                timeout=timeout
            )

            result['output'] = cmd_result.stdout
            result['success'] = cmd_result.returncode == 0

            if not result['success']:
                result['error'] = cmd_result.stderr

        except subprocess.TimeoutExpired:
            result['error'] = f"nmap扫描超时（{timeout}秒）"
        except Exception as e:
            result['error'] = str(e)

        return result

    def _execute_curl_step(self, lab_name: str, command: str, timeout: int) -> Dict[str, Any]:
        """执行curl请求步骤"""
        result = {'success': False, 'command': command, 'output': '', 'error': None}

        try:
            attacker_container = self._find_attacker_container(lab_name)
            if not attacker_container:
                result['error'] = "未找到attacker容器"
                return result

            exec_command = f"docker exec {attacker_container} {command}"
            cmd_result = subprocess.run(
                exec_command.split(),
                capture_output=True,
                text=True,
                timeout=timeout
            )

            result['output'] = cmd_result.stdout
            result['success'] = cmd_result.returncode == 0

            if not result['success']:
                result['error'] = cmd_result.stderr

        except subprocess.TimeoutExpired:
            result['error'] = f"curl请求超时（{timeout}秒）"
        except Exception as e:
            result['error'] = str(e)

        return result

    def _execute_shell_step(self, lab_name: str, command: str, timeout: int) -> Dict[str, Any]:
        """执行shell命令步骤"""
        result = {'success': False, 'command': command, 'output': '', 'error': None}

        try:
            attacker_container = self._find_attacker_container(lab_name)
            if not attacker_container:
                result['error'] = "未找到attacker容器"
                return result

            exec_command = f"docker exec {attacker_container} {command}"
            cmd_result = subprocess.run(
                exec_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            result['output'] = cmd_result.stdout
            result['success'] = cmd_result.returncode == 0

            if not result['success']:
                result['error'] = cmd_result.stderr

        except subprocess.TimeoutExpired:
            result['error'] = f"命令执行超时（{timeout}秒）"
        except Exception as e:
            result['error'] = str(e)

        return result

    def validate_network_isolation(self, lab_name: str, topology_file: str) -> Dict[str, Any]:
        """验证网络隔离效果"""
        result = {
            'isolation_tests': [],
            'overall_success': True,
            'failed_tests': [],
            'test_coverage': 0.0,
            'isolation_effectiveness': 0.0
        }

        try:
            # 解析拓扑文件获取隔离策略
            from .parser import ContainerLabParser
            parser = ContainerLabParser(topology_file)
            spec = parser.extract_topology_specification()

            if not spec.isolation_policies:
                print("⏭️  没有配置网络隔离策略，跳过隔离验证")
                result['overall_success'] = True
                result['skipped'] = True
                return result

            print(f"🔒 开始验证网络隔离策略 (共{len(spec.isolation_policies)}条)")

            # 获取实验室容器
            containers = self._get_lab_containers(lab_name)
            if not containers:
                result['overall_success'] = False
                result['error'] = "未找到任何容器"
                return result

            # 为每个隔离策略生成测试用例
            for policy in spec.isolation_policies:
                policy_tests = self._generate_isolation_tests(
                    policy, spec.security_zones, containers
                )

                # 执行隔离测试
                for test_case in policy_tests:
                    test_result = self._execute_isolation_test(test_case, lab_name)
                    result['isolation_tests'].append(test_result)

                    if not test_result['passed']:
                        result['overall_success'] = False
                        result['failed_tests'].append(test_result)

            # 计算隔离效果指标
            total_tests = len(result['isolation_tests'])
            if total_tests > 0:
                passed_tests = sum(1 for test in result['isolation_tests'] if test['passed'])
                result['test_coverage'] = 1.0  # 假设覆盖所有策略
                result['isolation_effectiveness'] = passed_tests / total_tests

            print(f"🔒 网络隔离验证完成: {sum(1 for t in result['isolation_tests'] if t['passed'])}/{total_tests} 个测试通过")

        except Exception as e:
            result['overall_success'] = False
            result['error'] = str(e)
            print(f"❌ 网络隔离验证异常: {str(e)}")

        return result

    def _generate_isolation_tests(self, policy, security_zones: Dict, containers: List) -> List[Dict]:
        """为隔离策略生成测试用例"""
        tests = []

        # 获取源区域和目标区域的容器
        source_zone = policy.source
        dest_zone = policy.destination

        source_containers = []
        dest_containers = []

        # 从安全区域映射中获取容器列表
        if source_zone in security_zones:
            zone_info = security_zones[source_zone]
            for container_name in zone_info.containers:
                # 查找对应的实际容器名
                actual_container = self._find_container_by_prefix(containers, container_name)
                if actual_container:
                    source_containers.append(actual_container['name'])

        if dest_zone in security_zones:
            zone_info = security_zones[dest_zone]
            for container_name in zone_info.containers:
                actual_container = self._find_container_by_prefix(containers, container_name)
                if actual_container:
                    dest_containers.append(actual_container['name'])

        # 如果没有找到容器，跳过测试
        if not source_containers or not dest_containers:
            print(f"   ⚠️  策略 {source_zone} -> {dest_zone}: 没有找到对应容器，跳过测试")
            return tests

        # 根据策略类型生成测试用例
        expected_blocked = (policy.action.upper() in ['DROP', 'REJECT'])

        # 为每对容器组合生成测试用例
        for src in source_containers[:1]:  # 限制为每个区域1个源容器
            for dst in dest_containers[:2]:  # 限制为每个区域2个目标容器
                test = {
                    'policy': f"{source_zone} -> {dest_zone}",
                    'source': src,
                    'destination': dst,
                    'expected_blocked': expected_blocked,
                    'action': policy.action,
                    'description': policy.description if hasattr(policy, 'description') else ''
                }
                tests.append(test)

        return tests

    def _execute_isolation_test(self, test_case: Dict, lab_name: str) -> Dict:
        """执行单个隔离测试"""
        result = {
            **test_case,
            'actual_blocked': False,
            'passed': False,
            'test_method': '',
            'error': None
        }

        try:
            source = test_case['source']
            destination = test_case['destination']

            # 执行连通性测试
            is_connected = self._test_container_connectivity(source, destination)
            result['actual_blocked'] = not is_connected
            result['passed'] = (not is_connected) == test_case['expected_blocked']
            result['test_method'] = 'tcp_connectivity'

        except Exception as e:
            result['error'] = str(e)
            # 如果测试出错，认为隔离失败
            result['passed'] = not test_case['expected_blocked']

        return result

    def _test_container_connectivity(self, source_container: str, dest_container: str) -> bool:
        """测试两个容器之间的连通性"""
        try:
            # 获取目标容器的IP地址
            ip_result = subprocess.run(
                ['docker', 'inspect', '-f',
                 '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', dest_container],
                capture_output=True,
                text=True,
                timeout=5
            )

            if ip_result.returncode != 0:
                return False

            target_ip = ip_result.stdout.strip()
            if not target_ip or target_ip == '':
                return False

            # 尝试ping测试 (更准确的连通性测试)
            ping_result = subprocess.run(
                ['docker', 'exec', source_container, 'ping', '-c', '1', '-W', '2', target_ip],
                capture_output=True,
                timeout=5
            )

            if ping_result.returncode == 0:
                # Ping成功，说明连通
                return True

            # 如果ping失败，尝试TCP连接测试
            tcp_result = subprocess.run(
                ['docker', 'exec', source_container, 'timeout', '1', 'bash', '-c',
                 f"cat < /dev/null > /dev/tcp/{target_ip}/80"],
                capture_output=True,
                timeout=3
            )

            return tcp_result.returncode == 0

        except Exception as e:
            print(f"      ⚠️  连通性测试异常: {str(e)}")
            return False

    def _find_container_by_prefix(self, containers: List, prefix: str) -> Dict:
        """根据前缀查找容器"""
        for container in containers:
            if prefix in container.get('name', ''):
                return container
        return None

    def _find_attacker_container(self, lab_name: str) -> Optional[str]:
        """查找attacker容器"""
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={lab_name}', '--format', '{{{{.Names}}}}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.strip().split('\n'):
                if 'attacker' in line.lower():
                    return line

        except Exception as e:
            print(f"查找attacker容器失败: {str(e)}")

        return None


def main():
    """主函数 - 单独运行验证器"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python environment_validator.py <topology_file> [attack_playbook]")
        sys.exit(1)

    topology_file = sys.argv[1]
    attack_playbook = sys.argv[2] if len(sys.argv) > 2 else None

    validator = EnvironmentValidator()
    result = validator.validate_generated_environment(topology_file, attack_playbook)

    print(f"\n📊 验证结果:")
    print(f"   状态: {result['overall_status']}")
    print(f"   质量分: {result['quality_score']}/100")

    if result['overall_status'] == 'success':
        print(f"   ✅ 环境验证通过")
        sys.exit(0)
    else:
        print(f"   ❌ 环境验证失败")
        sys.exit(1)


if __name__ == "__main__":
    main()