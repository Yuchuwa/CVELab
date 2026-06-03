"""Vulhub 转换器单元测试

测试 VulhubParser 和 AnsiblePlaybookGenerator。
"""

import pytest
import yaml
from pathlib import Path
from unittest.mock import patch

from clab_builder.atomizer.output.vulhub_converter import (
    VulhubParser,
    AnsiblePlaybookGenerator,
    VulhubService,
    VulhubEnvironment,
    convert_vulhub_to_ansible,
)


# ── VulhubParser 测试 ──────────────────────────────────────────────


@pytest.mark.unit
class TestVulhubParser:
    """Vulhub docker-compose.yml 解析器测试"""

    def _make_compose(self, tmp_path, services_yaml, readme=""):
        """辅助: 创建临时 vulhub 目录结构"""
        vulhub_dir = tmp_path / "data" / "vulhub" / "testcat" / "CVE-2021-TEST"
        vulhub_dir.mkdir(parents=True)
        (vulhub_dir / "docker-compose.yml").write_text(
            yaml.dump({"services": services_yaml}, default_flow_style=False)
        )
        if readme:
            (vulhub_dir / "README.md").write_text(readme)
        return str(vulhub_dir)

    def test_single_service(self, tmp_path):
        """单服务环境"""
        vulhub_dir = self._make_compose(tmp_path, {
            "web": {
                "image": "vulhub/log4j:2.14.1",
                "ports": ["8983:8983"],
            }
        })

        env = VulhubParser().parse(vulhub_dir)
        assert env.cve_id == "CVE-2021-TEST"
        assert env.category == "testcat"
        assert len(env.services) == 1
        assert env.services[0].image == "vulhub/log4j:2.14.1"
        assert env.services[0].ports == ["8983:8983"]
        assert env.services[0].is_main_target is True
        assert env.main_image == "vulhub/log4j:2.14.1"
        assert env.main_ports == [8983]

    def test_multi_service_with_depends(self, tmp_path):
        """多服务 + depends_on"""
        vulhub_dir = self._make_compose(tmp_path, {
            "mysql": {
                "image": "mysql:5.5",
                "environment": {"MYSQL_ROOT_PASSWORD": "root"},
            },
            "web": {
                "image": "vulhub/phpmyadmin:4.8.1",
                "ports": ["8080:80"],
                "depends_on": ["mysql"],
            },
        })

        env = VulhubParser().parse(vulhub_dir)
        assert len(env.services) == 2
        assert env.main_service.name == "web"
        assert env.main_service.depends_on == ["mysql"]
        assert env.services[0].name == "mysql"

    def test_env_dict_and_list(self, tmp_path):
        """environment 支持字典和列表两种格式"""
        # dict 格式
        vulhub_dir = self._make_compose(tmp_path, {
            "app": {
                "image": "test:latest",
                "environment": {"FOO": "bar", "BAZ": "123"},
            }
        })
        env = VulhubParser().parse(vulhub_dir)
        assert env.services[0].environment == {"FOO": "bar", "BAZ": "123"}

        # list 格式
        vulhub_dir2 = self._make_compose(tmp_path / "2", {
            "app": {
                "image": "test:latest",
                "environment": ["FOO=bar", "BAZ=123"],
            }
        })
        env2 = VulhubParser().parse(vulhub_dir2)
        assert env2.services[0].environment == {"FOO": "bar", "BAZ": "123"}

    def test_volumes(self, tmp_path):
        """volumes 解析"""
        vulhub_dir = self._make_compose(tmp_path, {
            "web": {
                "image": "test:latest",
                "volumes": ["./config.ini:/etc/config.ini"],
            }
        })
        env = VulhubParser().parse(vulhub_dir)
        assert env.services[0].volumes == ["./config.ini:/etc/config.ini"]

    def test_readme_content(self, tmp_path):
        """README 读取"""
        vulhub_dir = self._make_compose(
            tmp_path,
            {"web": {"image": "test:latest"}},
            readme="# CVE-2021-TEST\nThis is a test writeup.",
        )
        env = VulhubParser().parse(vulhub_dir)
        assert "CVE-2021-TEST" in env.readme_content

    def test_no_compose_file(self, tmp_path):
        """缺少 docker-compose.yml 报错"""
        with pytest.raises(FileNotFoundError):
            VulhubParser().parse(str(tmp_path))


# ── AnsiblePlaybookGenerator 测试 ──────────────────────────────────


@pytest.mark.unit
class TestAnsiblePlaybookGenerator:
    """Ansible playbook 生成测试"""

    def _make_env(self):
        return VulhubEnvironment(
            cve_id="CVE-2021-44228",
            category="log4j",
            services=[
                VulhubService(
                    name="solr",
                    image="vulhub/log4j:2.14.1",
                    ports=["8983:8983"],
                    is_main_target=True,
                ),
            ],
            main_service=VulhubService(
                name="solr",
                image="vulhub/log4j:2.14.1",
                ports=["8983:8983"],
                is_main_target=True,
            ),
        )

    def test_generate_basic(self):
        """基本 playbook 生成"""
        env = self._make_env()
        playbook_yaml = AnsiblePlaybookGenerator().generate(env)
        playbook = yaml.safe_load(playbook_yaml)

        assert len(playbook) == 1
        play = playbook[0]
        assert play["name"] == "Deploy CVE-2021-44228"
        assert play["hosts"] == "localhost"
        assert play["gather_facts"] is False

        # 应有: 创建网络 + 启动容器 + 等待就绪
        assert len(play["tasks"]) == 3

        # 第一个任务是创建网络
        assert "community.docker.docker_network" in play["tasks"][0]

        # 第二个任务是启动容器
        docker_task = play["tasks"][1]
        assert "community.docker.docker_container" in docker_task
        container_cfg = docker_task["community.docker.docker_container"]
        assert container_cfg["image"] == "vulhub/log4j:2.14.1"
        assert container_cfg["published_ports"] == ["8983:8983"]

    def test_topo_sort(self):
        """依赖排序: mysql 在 web 之前"""
        env = VulhubEnvironment(
            cve_id="CVE-2018-12613",
            category="phpmyadmin",
            services=[
                VulhubService(
                    name="mysql",
                    image="mysql:5.5",
                    environment={"MYSQL_ROOT_PASSWORD": "root"},
                ),
                VulhubService(
                    name="web",
                    image="vulhub/phpmyadmin:4.8.1",
                    ports=["8080:80"],
                    depends_on=["mysql"],
                    is_main_target=True,
                ),
            ],
            main_service=VulhubService(
                name="web",
                image="vulhub/phpmyadmin:4.8.1",
                ports=["8080:80"],
                depends_on=["mysql"],
                is_main_target=True,
            ),
        )

        gen = AnsiblePlaybookGenerator()
        sorted_svcs = gen._topo_sort(env.services)
        names = [s.name for s in sorted_svcs]
        assert names.index("mysql") < names.index("web")

    def test_multi_service_playbook(self):
        """多服务 playbook"""
        env = VulhubEnvironment(
            cve_id="CVE-2018-12613",
            category="phpmyadmin",
            services=[
                VulhubService(name="mysql", image="mysql:5.5",
                              environment={"MYSQL_ROOT_PASSWORD": "root"}),
                VulhubService(name="web", image="vulhub/phpmyadmin:4.8.1",
                              ports=["8080:80"], depends_on=["mysql"],
                              is_main_target=True),
            ],
            main_service=VulhubService(
                name="web", image="vulhub/phpmyadmin:4.8.1",
                ports=["8080:80"], depends_on=["mysql"], is_main_target=True,
            ),
        )

        playbook_yaml = AnsiblePlaybookGenerator().generate(env)
        playbook = yaml.safe_load(playbook_yaml)
        tasks = playbook[0]["tasks"]

        # 创建网络 + mysql容器 + web容器 + 等待就绪
        task_names = [t["name"] for t in tasks]
        assert any("mysql" in n for n in task_names)
        assert any("web" in n for n in task_names)
        assert any("Wait" in n for n in task_names)


# ── 一站式转换函数 ──────────────────────────────────────────────────


@pytest.mark.unit
class TestConvertVulhubToAnsible:
    """convert_vulhub_to_ansible 端到端测试（mock parse）"""

    def test_writes_file(self, tmp_path):
        """验证输出文件"""
        vulhub_dir = tmp_path / "data" / "vulhub" / "cat" / "CVE-2021-TEST"
        vulhub_dir.mkdir(parents=True)
        (vulhub_dir / "docker-compose.yml").write_text(yaml.dump({
            "services": {"web": {"image": "vulhub/test:1.0"}}
        }))

        output_path = tmp_path / "out" / "deploy.yaml"
        result = convert_vulhub_to_ansible(str(vulhub_dir), str(output_path))

        assert output_path.exists()
        assert "Deploy CVE-2021-TEST" in output_path.read_text()
