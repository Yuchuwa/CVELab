"""增强的网络连通性测试模块

提供全面的网络连通性验证：
- ICMP ping测试
- TCP/UDP端口连接测试
- DNS解析验证
- 路由路径验证
- 带宽和延迟测量
"""
import subprocess
import time
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ConnectivityTestResult:
    """连通性测试结果"""
    test_type: str
    source: str
    destination: str
    success: bool
    details: Dict[str, Any]
    duration_ms: float
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ICMPTestResult(ConnectivityTestResult):
    """ICMP ping测试结果"""
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss: float = 0.0
    min_rtt: float = 0.0
    max_rtt: float = 0.0
    avg_rtt: float = 0.0
    jitter: float = 0.0


@dataclass
class TCPTestResult(ConnectivityTestResult):
    """TCP连接测试结果"""
    port: int = 0
    connection_time_ms: float = 0.0
    banner: str = ""


@dataclass
class RouteTestResult(ConnectivityTestResult):
    """路由测试结果"""
    hop_count: int = 0
    path: List[str] = None
    total_hops: int = 0

    def __post_init__(self):
        if self.path is None:
            self.path = []


class EnhancedConnectivityTester:
    """增强的连通性测试器"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.test_results: List[ConnectivityTestResult] = []

    def comprehensive_connectivity_test(
        self,
        source_container: str,
        target_container: str,
        test_ports: List[int] = None
    ) -> Dict[str, Any]:
        """综合连通性测试"""

        # 获取目标容器IP
        target_ip = self._get_container_ip(target_container)
        if not target_ip:
            return {
                'overall_success': False,
                'error': '无法获取目标容器IP地址',
                'tests': []
            }

        print(f"🔍 综合连通性测试: {source_container} -> {target_container} ({target_ip})")

        test_results = {
            'source': source_container,
            'destination': target_container,
            'target_ip': target_ip,
            'tests': {},
            'overall_success': True
        }

        # 1. ICMP Ping测试
        print(f"   📡 ICMP Ping测试...")
        icmp_result = self._test_icmp_ping(source_container, target_ip)
        test_results['tests']['icmp_ping'] = icmp_result
        if not icmp_result['success']:
            test_results['overall_success'] = False

        # 2. TCP端口连接测试
        if test_ports:
            print(f"   🔌 TCP端口连接测试 (端口: {test_ports})...")
            tcp_results = []
            for port in test_ports:
                tcp_result = self._test_tcp_connection(source_container, target_ip, port)
                tcp_results.append(tcp_result)
                if not tcp_result['success']:
                    # 非关键端口失败不影响总体成功
                    pass

            test_results['tests']['tcp_connectivity'] = tcp_results

        # 3. DNS解析测试
        print(f"   🌐 DNS解析测试...")
        dns_result = self._test_dns_resolution(source_container, target_container)
        test_results['tests']['dns_resolution'] = dns_result

        # 4. 路由路径验证
        print(f"   🛤️  路由路径验证...")
        route_result = self._test_route_tracing(source_container, target_ip)
        test_results['tests']['route_tracing'] = route_result

        # 5. 带宽和延迟测试（可选）
        print(f"   ⚡ 带宽延迟测试...")
        perf_result = self._test_performance(source_container, target_ip)
        test_results['tests']['performance'] = perf_result

        return test_results

    def _get_container_ip(self, container_name: str) -> Optional[str]:
        """获取容器IP地址"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '-f',
                 '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', container_name],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                ip = result.stdout.strip()
                if ip and ip != '<no value>':
                    return ip

        except Exception as e:
            print(f"      ⚠️  获取容器IP失败: {e}")

        return None

    def _test_icmp_ping(self, source_container: str, target_ip: str) -> Dict[str, Any]:
        """ICMP ping测试"""
        start_time = time.time()

        try:
            # 发送5个ping包
            ping_result = subprocess.run(
                ['docker', 'exec', source_container, 'ping', '-c', '5', '-W', '2', target_ip],
                capture_output=True,
                text=True,
                timeout=15
            )

            duration = (time.time() - start_time) * 1000  # 转换为毫秒

            # 解析ping结果
            output = ping_result.stdout + ping_result.stderr

            # 提取ping统计信息
            packets_sent = 5
            packets_received = output.count('bytes from') + output.count('time=')

            if packets_received == 0:
                return {
                    'success': False,
                    'error': 'ping无响应',
                    'packets_sent': packets_sent,
                    'packets_received': 0,
                    'packet_loss': 100.0,
                    'duration_ms': duration
                }

            # 提取RTT时间
            rtt_pattern = r'time[=<](\d+\.?\d*)\s*ms'
            rtt_matches = re.findall(rtt_pattern, output)

            if rtt_matches:
                rtts = [float(rtt) for rtt in rtt_matches]
                min_rtt = min(rtts)
                max_rtt = max(rtts)
                avg_rtt = sum(rtts) / len(rtts)
                jitter = max(abs(rtt - avg_rtt) for rtt in rtts)
            else:
                min_rtt = max_rtt = avg_rtt = jitter = 0.0

            packet_loss = ((packets_sent - packets_received) / packets_sent) * 100

            success = (packet_loss < 100) and (packets_received > 0)

            print(f"      ✅ Ping成功: {packets_received}/{packets_sent} 包, 丢包率 {packet_loss:.1f}%, 平均RTT {avg_rtt:.2f}ms")

            return {
                'success': success,
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'packet_loss': packet_loss,
                'min_rtt': min_rtt,
                'max_rtt': max_rtt,
                'avg_rtt': avg_rtt,
                'jitter': jitter,
                'duration_ms': duration
            }

        except subprocess.TimeoutExpired:
            print(f"      ❌ Ping超时")
            return {
                'success': False,
                'error': 'ping超时',
                'packets_sent': 5,
                'packets_received': 0,
                'packet_loss': 100.0,
                'duration_ms': (time.time() - start_time) * 1000
            }
        except Exception as e:
            print(f"      ❌ Ping测试异常: {e}")
            return {
                'success': False,
                'error': str(e),
                'duration_ms': (time.time() - start_time) * 1000
            }

    def _test_tcp_connection(self, source_container: str, target_ip: str, port: int) -> Dict[str, Any]:
        """TCP端口连接测试"""
        start_time = time.time()

        try:
            # 使用timeout和bash测试TCP连接
            test_result = subprocess.run(
                ['docker', 'exec', source_container, 'timeout', '2', 'bash', '-c',
                 f"cat < /dev/null > /dev/tcp/{target_ip}/{port}"],
                capture_output=True,
                timeout=5
            )

            duration = (time.time() - start_time) * 1000

            if test_result.returncode == 0:
                print(f"      ✅ 端口 {port} 可达 ({duration:.1f}ms)")
                return {
                    'success': True,
                    'port': port,
                    'connection_time_ms': duration,
                    'protocol': 'tcp'
                }
            else:
                print(f"      ❌ 端口 {port} 不可达")
                return {
                    'success': False,
                    'port': port,
                    'error': '连接被拒绝或超时',
                    'duration_ms': duration
                }

        except subprocess.TimeoutExpired:
            print(f"      ❌ 端口 {port} 连接超时")
            return {
                'success': False,
                'port': port,
                'error': '连接超时',
                'duration_ms': 2000
            }
        except Exception as e:
            print(f"      ❌ 端口 {port} 测试异常: {e}")
            return {
                'success': False,
                'port': port,
                'error': str(e)
            }

    def _test_dns_resolution(self, source_container: str, target_container: str) -> Dict[str, Any]:
        """DNS解析测试"""
        try:
            # 尝试通过容器名解析
            start_time = time.time()

            nslookup_result = subprocess.run(
                ['docker', 'exec', source_container, 'nslookup', target_container],
                capture_output=True,
                text=True,
                timeout=5
            )

            duration = (time.time() - start_time) * 1000

            if nslookup_result.returncode == 0:
                print(f"      ✅ DNS解析成功 ({duration:.1f}ms)")
                return {
                    'success': True,
                    'resolution_time_ms': duration,
                    'method': 'nslookup'
                }
            else:
                # 尝试使用ping解析
                ping_result = subprocess.run(
                    ['docker', 'exec', source_container, 'ping', '-c', '1', target_container],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if ping_result.returncode == 0:
                    print(f"      ✅ DNS解析通过ping成功 ({duration:.1f}ms)")
                    return {
                        'success': True,
                        'resolution_time_ms': duration,
                        'method': 'ping'
                    }

                print(f"      ❌ DNS解析失败")
                return {
                    'success': False,
                    'error': '无法解析目标主机名',
                    'duration_ms': duration
                }

        except Exception as e:
            print(f"      ❌ DNS测试异常: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _test_route_tracing(self, source_container: str, target_ip: str) -> Dict[str, Any]:
        """路由路径测试"""
        try:
            # 使用traceroute或tracepath
            start_time = time.time()

            # 尝试traceroute
            traceroute_result = subprocess.run(
                ['docker', 'exec', source_container, 'traceroute', '-n', '-m', '10', '-w', '1', target_ip],
                capture_output=True,
                text=True,
                timeout=15
            )

            duration = (time.time() - start_time) * 1000

            if traceroute_result.returncode == 0:
                output = traceroute_result.stdout

                # 解析跳数
                hops = []
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('traceroute'):
                        # 提取跳数信息
                        hop_match = re.match(r'^\s*(\d+)', line)
                        if hop_match:
                            hop_num = int(hop_match.group(1))
                            # 提取IP地址
                            ip_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_matches:
                                hops.append({
                                    'hop': hop_num,
                                    'ip': ip_matches[0]
                                })

                if hops:
                    print(f"      ✅ 路由追踪成功: {len(hops)} 跳到达目标")
                    return {
                        'success': True,
                        'hop_count': len(hops),
                        'path': hops,
                        'duration_ms': duration
                    }

            # 如果traceroute失败，尝试简单的路由表检查
            route_result = subprocess.run(
                ['docker', 'exec', source_container, 'ip', 'route', 'get', target_ip],
                capture_output=True,
                text=True,
                timeout=5
            )

            if route_result.returncode == 0:
                route_info = route_result.stdout.strip()
                print(f"      ✅ 路由查询成功: {route_info}")
                return {
                    'success': True,
                    'route_info': route_info,
                    'method': 'route_get',
                    'duration_ms': duration
                }

            print(f"      ❌ 路由追踪失败")
            return {
                'success': False,
                'error': '无法追踪路由路径',
                'duration_ms': duration
            }

        except subprocess.TimeoutExpired:
            print(f"      ❌ 路由追踪超时")
            return {
                'success': False,
                'error': '路由追踪超时',
                'duration_ms': 15000
            }
        except Exception as e:
            print(f"      ⚠️  路由测试异常: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _test_performance(self, source_container: str, target_ip: str) -> Dict[str, Any]:
        """性能测试（延迟和带宽）"""
        try:
            # 使用iperf3或简单的ping测试
            start_time = time.time()

            # 先尝试iperf3
            iperf_result = subprocess.run(
                ['docker', 'exec', source_container, 'iperf3', '-c', target_ip, '-t', '1', '-J'],
                capture_output=True,
                text=True,
                timeout=10
            )

            duration = (time.time() - start_time) * 1000

            if iperf_result.returncode == 0:
                # 解析iperf3 JSON结果
                try:
                    iperf_data = json.loads(iperf_result.stdout)
                    bits_per_second = iperf_data.get('end', {}).get('sum_received', {}).get('bits_per_second', 0)
                    bandwidth_mbps = bits_per_second / 1_000_000

                    print(f"      ✅ 带宽测试成功: {bandwidth_mbps:.2f} Mbps")
                    return {
                        'success': True,
                        'bandwidth_mbps': bandwidth_mbps,
                        'test_method': 'iperf3',
                        'duration_ms': duration
                    }
                except json.JSONDecodeError:
                    pass

            # 如果没有iperf3，使用ping进行简单延迟测试
            ping_result = subprocess.run(
                ['docker', 'exec', source_container, 'ping', '-c', '10', '-i', '0.1', target_ip],
                capture_output=True,
                text=True,
                timeout=15
            )

            if ping_result.returncode == 0:
                # 解析ping延迟
                rtt_pattern = r'time[=<](\d+\.?\d*)\s*ms'
                rtt_matches = re.findall(rtt_pattern, ping_result.stdout)

                if rtt_matches:
                    rtts = [float(rtt) for rtt in rtt_matches]
                    avg_latency = sum(rtts) / len(rtts)

                    print(f"      ✅ 延迟测试成功: 平均 {avg_latency:.2f}ms")
                    return {
                        'success': True,
                        'avg_latency_ms': avg_latency,
                        'test_method': 'ping',
                        'duration_ms': duration
                    }

            print(f"      ⚠️  性能测试跳过（需要iperf3）")
            return {
                'success': False,
                'error': '没有可用的性能测试工具',
                'skipped': True,
                'duration_ms': duration
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': '性能测试超时',
                'duration_ms': 10000
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def batch_connectivity_test(
        self,
        lab_name: str,
        test_pairs: List[Tuple[str, str, List[int]]]
    ) -> Dict[str, Any]:
        """批量连通性测试"""

        print(f"🚀 开始批量连通性测试 ({len(test_pairs)} 对)")

        results = {
            'lab_name': lab_name,
            'test_pairs': len(test_pairs),
            'results': [],
            'summary': {
                'total_tests': 0,
                'successful_tests': 0,
                'failed_tests': 0,
                'success_rate': 0.0
            }
        }

        for source, target, ports in test_pairs:
            print(f"\n📋 测试对: {source} -> {target}")
            test_result = self.comprehensive_connectivity_test(source, target, ports)
            results['results'].append(test_result)

            # 更新统计
            results['summary']['total_tests'] += 1
            if test_result['overall_success']:
                results['summary']['successful_tests'] += 1
            else:
                results['summary']['failed_tests'] += 1

        # 计算成功率
        if results['summary']['total_tests'] > 0:
            results['summary']['success_rate'] = (
                results['summary']['successful_tests'] / results['summary']['total_tests']
            )

        return results


def main():
    """测试增强的连通性测试功能"""
    tester = EnhancedConnectivityTester()

    print("🧪 增强的连通性测试模块")
    print("这个模块需要运行的容器才能进行实际测试")


if __name__ == "__main__":
    main()