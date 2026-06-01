"""Pytest配置和共享fixtures"""

import pytest
import sys
import tempfile
import os
from pathlib import Path
import yaml
from typing import Dict, Any, List

# 添加项目路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))


@pytest.fixture
def sample_topology_data() -> Dict[str, Any]:
    """示例拓扑数据"""
    return {
        'name': 'test-lab',
        'description': 'Test laboratory for unit testing',
        'topology': {
            'nodes': {
                'attacker': {
                    'kind': 'linux',
                    'image': 'kalilinux/kali-rolling:latest',
                    'labels': {
                        'role': 'attacker',
                        'security_zone': 'attacker_zone'
                    }
                },
                'router': {
                    'kind': 'linux',
                    'image': 'frrouting/frr:latest',
                    'labels': {
                        'role': 'router',
                        'security_zone': 'dmz_zone'
                    },
                    'sysctls': {
                        'net.ipv4.ip_forward': '1'
                    }
                },
                'web-server': {
                    'kind': 'linux',
                    'image': 'nginx:latest',
                    'labels': {
                        'role': 'web_server',
                        'security_zone': 'dmz_zone'
                    },
                    'ports': ['80/tcp', '443/tcp']
                },
                'database': {
                    'kind': 'linux',
                    'image': 'mysql:latest',
                    'labels': {
                        'role': 'database',
                        'security_zone': 'internal_zone'
                    },
                    'ports': ['3306/tcp']
                }
            },
            'links': [
                {'endpoints': ['attacker:eth1', 'router:eth1']},
                {'endpoints': ['router:eth2', 'web-server:eth1']},
                {'endpoints': ['router:eth3', 'database:eth1']}
            ]
        },
        'isolation_policies': [
            {
                'source': 'attacker_zone',
                'destination': 'dmz_zone',
                'action': 'ACCEPT',
                'allowed_ports': [80, 443],
                'log': True,
                'description': 'Allow attacker to access web services'
            },
            {
                'source': 'attacker_zone',
                'destination': 'internal_zone',
                'action': 'DROP',
                'log': True,
                'description': 'Block attacker from internal network'
            }
        ]
    }


@pytest.fixture
def sample_topology_file(sample_topology_data: Dict[str, Any], tmp_path: Path) -> str:
    """创建临时拓扑文件"""
    topology_file = tmp_path / "test_topology.yaml"
    with open(topology_file, 'w', encoding='utf-8') as f:
        yaml.dump(sample_topology_data, f)
    return str(topology_file)


@pytest.fixture
def sample_isolation_policies() -> List[Dict[str, Any]]:
    """示例隔离策略"""
    return [
        {
            'source': 'attacker_zone',
            'destination': 'dmz_zone',
            'action': 'ACCEPT',
            'allowed_ports': [80, 443],
            'log': True,
            'description': 'Allow attacker to access web services'
        },
        {
            'source': 'attacker_zone',
            'destination': 'internal_zone',
            'action': 'DROP',
            'log': True,
            'description': 'Block attacker from internal network'
        },
        {
            'source': 'dmz_zone',
            'destination': 'internal_zone',
            'action': 'DROP',
            'log': True,
            'description': 'Block DMZ from internal network'
        }
    ]


@pytest.fixture
def mock_containers() -> List[Dict[str, Any]]:
    """模拟Docker容器"""
    return [
        {
            'name': 'test-lab-attacker',
            'status': 'Up 2 hours',
            'state': 'running'
        },
        {
            'name': 'test-lab-router',
            'status': 'Up 2 hours',
            'state': 'running'
        },
        {
            'name': 'test-lab-web-server',
            'status': 'Up 2 hours',
            'state': 'running'
        },
        {
            'name': 'test-lab-database',
            'status': 'Up 2 hours',
            'state': 'running'
        }
    ]


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """创建临时工作空间"""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def mock_docker_networks() -> List[str]:
    """模拟Docker网络"""
    return [
        '172.17.0.0/16',
        '172.18.0.0/16',
        '10.100.0.0/24'
    ]


@pytest.fixture(scope="session")
def docker_available() -> bool:
    """检查Docker是否可用"""
    try:
        import subprocess
        result = subprocess.run(
            ['docker', '--version'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.fixture
def skip_if_no_docker(docker_available: bool) -> None:
    """如果Docker不可用则跳过测试"""
    if not docker_available:
        pytest.skip("Docker not available")


@pytest.fixture
def skip_if_no_containerlab(docker_available: bool) -> None:
    """如果ContainerLab不可用则跳过测试"""
    if not docker_available:
        pytest.skip("Docker not available")
        return

    try:
        import subprocess
        result = subprocess.run(
            ['clab', '--version'],
            capture_output=True,
            timeout=5
        )
        if result.returncode != 0:
            pytest.skip("ContainerLab not available")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("ContainerLab not available")


# 测试数据目录
@pytest.fixture
def test_data_dir() -> Path:
    """测试数据目录"""
    test_data = Path(__file__).parent / "test_data"
    test_data.mkdir(exist_ok=True)
    return test_data


# 示例YAML文件目录
@pytest.fixture
def examples_dir() -> Path:
    """示例YAML文件目录"""
    return project_root / "examples"


# Mock subprocess results
@pytest.fixture
def mock_subprocess_result(mocker):
    """Mock subprocess结果"""
    def _mock_result(returncode=0, stdout="", stderr=""):
        mock_result = mocker.MagicMock()
        mock_result.returncode = returncode
        mock_result.stdout = stdout
        mock_result.stderr = stderr
        return mock_result
    return _mock_result


# 性能测试fixture
@pytest.fixture
def benchmark_timer():
    """性能计时器"""
    import time
    times = []

    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def __enter__(self):
            self.start_time = time.time()
            return self

        def __exit__(self, *args):
            self.end_time = time.time()
            times.append(self.end_time - self.start_time)

        @property
        def duration(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

    return Timer


# 网络测试fixture
@pytest.fixture
def network_test_config():
    """网络测试配置"""
    return {
        'timeout': 10,
        'ping_count': 3,
        'test_ports': [80, 443, 22, 3306],
        'expected_latency_ms': 100,
        'max_packet_loss': 5.0
    }


# CVE测试数据
@pytest.fixture
def sample_cve_data() -> Dict[str, Any]:
    """示例CVE数据"""
    return {
        'cve_id': 'CVE-2021-44228',
        'name': 'Apache Log4j RCE',
        'cvss_score': '10.0',
        'attack_vector': 'network',
        'complexity': 'low',
        'required_dependencies': ['java', 'ldap'],
        'network_requirements': ['http', 'ldap'],
        'isolation_requirements': ['dmz']
    }


# 日志捕获fixture
@pytest.fixture
def capture_logs(caplog):
    """捕获日志"""
    caplog.set_level(logging.DEBUG)
    return caplog


# 环境变量设置
@pytest.fixture
def set_env_vars(monkeypatch):
    """设置环境变量"""
    def _set_vars(env_vars: Dict[str, str]):
        for key, value in env_vars.items():
            monkeypatch.setenv(key, value)
    return _set_vars