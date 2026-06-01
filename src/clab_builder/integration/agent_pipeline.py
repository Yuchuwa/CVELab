"""
Agent驱动的CVE原子化Pipeline

完整流程：
1. 启动CVE环境容器（独立Docker容器）
2. 启动Agent容器（独立Docker容器，含Claude Code SDK）
3. Agent接收信息输入（CVE资料、exploit参考、writeup）
4. Agent自主分析、编写exploit、执行、验证
5. 生成验证后的Ansible配置和exploit playbook
"""

from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..environment import CVEEnvironmentManager
from ..agent import SecurityResearcherAgent, CVEInput, AgentOutput
from ..playbook import AnsibleConfigGenerator, ExploitPlaybookGenerator


@dataclass
class PipelineConfig:
    """Pipeline配置"""
    cve_id: str
    docker_image: str
    ports: List[int]
    cve_description: str
    exploit_references: List[str]
    writeups: List[str]
    output_dir: str = "/tmp/cve_playbooks"
    network_name: str = "cve-network"
    agent_container_image: str = "anthropic/claude-code:latest"


class AgentDrivenCVEPipeline:
    """
    Agent驱动的CVE原子化Pipeline

    核心特性：
    - CVE环境和Agent使用独立Docker容器
    - 网络隔离
    - Agent只接收信息输入，自主完成复现
    - 输出验证后的Ansible配置和playbook
    """

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 初始化组件
        self.cve_manager = CVEEnvironmentManager(network_name=config.network_name)
        self.agent = SecurityResearcherAgent(
            agent_container_image=config.agent_container_image
        )
        self.ansible_gen = AnsibleConfigGenerator()
        self.playbook_gen = ExploitPlaybookGenerator()

    def run(self) -> Dict[str, Any]:
        """
        执行完整的Agent驱动pipeline

        Returns:
            Pipeline执行结果
        """
        print(f"🚀 启动Agent驱动CVE Pipeline: {self.config.cve_id}")
        print(f"   CVE镜像: {self.config.docker_image}")
        print(f"   Agent镜像: {self.config.agent_container_image}")
        print(f"   端口: {self.config.ports}")
        print(f"   网络: {self.config.network_name}")

        try:
            # Step 1: 启动CVE环境容器
            print(f"\n📍 Step 1: 启动CVE环境容器")
            cve_container = self.cve_manager.start_cve_container(
                cve_id=self.config.cve_id,
                docker_image=self.config.docker_image,
                ports=self.config.ports
            )
            print(f"✅ CVE容器已启动: {cve_container.container_name}")
            print(f"   IP: {cve_container.container_ip}")

            # Step 2: 准备Agent输入
            print(f"\n📍 Step 2: 准备Agent输入（CVE信息资料）")
            agent_input = CVEInput(
                cve_id=self.config.cve_id,
                description=self.config.cve_description,
                exploit_references=self.config.exploit_references,
                writeups=self.config.writeups,
                docker_image=self.config.docker_image,
                ports=self.config.ports,
                target_ip=cve_container.container_ip,
                environment_info={
                    'container_id': cve_container.container_id,
                    'container_name': cve_container.container_name,
                    'network': self.config.network_name
                }
            )
            print(f"✅ Agent输入已准备")
            print(f"   CVE资料已就绪，等待Agent自主分析")

            # Step 3: Agent处理CVE（在Docker容器中运行）
            print(f"\n📍 Step 3: Agent处理CVE（在容器中使用Claude Code SDK）")
            print(f"   Agent将自主：分析→决策→执行→验证")

            agent_output = self.agent.execute_agent_task(
                cve_input=agent_input,
                playbook_generator=self  # 传递self作为playbook生成器
            )

            if not agent_output.success:
                print(f"⚠️ Agent处理失败")
                print(f"   执行日志: {agent_output.execution_log}")
                return {
                    'success': False,
                    'error': 'Agent processing failed',
                    'execution_log': agent_output.execution_log,
                    'cve_id': self.config.cve_id
                }

            print(f"✅ Agent处理成功")
            print(f"   攻击路径: {len(agent_output.attack_path)} 个阶段")
            print(f"   MITRE映射: {len(agent_output.mitre_mapping)} 个阶段")
            print(f"   验证证据: {len(agent_output.verification_evidence)} 条")

            # Step 4: 保存输出
            print(f"\n📍 Step 4: 保存Ansible配置和exploit playbook")
            self._save_outputs(agent_output)

            # Step 5: 清理
            print(f"\n📍 Step 5: 清理容器")
            # 保持容器运行以便手动检查
            print(f"💡 容器保留运行，可手动清理")

            # 返回结果
            result = {
                'success': True,
                'cve_id': self.config.cve_id,
                'containers': {
                    'cve_container': {
                        'id': cve_container.container_id,
                        'name': cve_container.container_name,
                        'ip': cve_container.container_ip
                    },
                    'agent_container': {
                        'id': self.agent.container_id,
                        'image': self.config.agent_container_image
                    }
                },
                'agent_output': {
                    'success': agent_output.success,
                    'attack_path_stages': len(agent_output.attack_path),
                    'mitre_mapping_stages': len(agent_output.mitre_mapping),
                    'evidence_count': len(agent_output.verification_evidence)
                },
                'output_files': {
                    'ansible_config': str(self.output_dir / f"{self.config.cve_id}_ansible_config.yml"),
                    'exploit_playbook': str(self.output_dir / f"{self.config.cve_id}_exploit_playbook.yml"),
                    'execution_log': str(self.output_dir / f"{self.config.cve_id}_execution.log")
                },
                'execution_log': agent_output.execution_log
            }

            print(f"\n✅ Pipeline执行完成!")
            return result

        except Exception as e:
            error_msg = f"Pipeline执行出错: {str(e)}"
            print(f"\n❌ {error_msg}")
            import traceback
            traceback.print_exc()

            return {
                'success': False,
                'error': error_msg,
                'cve_id': self.config.cve_id
            }

    def generate(self, cve_id: str, docker_image: str, ports: List[int],
                attack_path: Dict[str, Any], mitre_mapping: Dict[str, List[str]],
                exploit_info: Dict[str, Any], verification: Dict[str, Any]):
        """
        Playbook生成接口（供Agent调用）
        """
        ansible_config = self.ansible_gen.generate(
            cve_id=cve_id,
            docker_image=docker_image,
            ports=ports
        )

        exploit_playbook = self.playbook_gen.generate(
            cve_id=cve_id,
            attack_path=attack_path,
            mitre_mapping=mitre_mapping,
            exploit_info=exploit_info,
            verification=verification
        )

        return ansible_config, exploit_playbook

    def _save_outputs(self, agent_output: AgentOutput):
        """保存输出文件"""
        # 保存Ansible配置
        config_file = self.output_dir / f"{agent_output.cve_id}_ansible_config.yml"
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write("# Ansible Configuration for CVE Environment\n")
            f.write(agent_output.ansible_config)

        # 保存Exploit Playbook
        playbook_file = self.output_dir / f"{agent_output.cve_id}_exploit_playbook.yml"
        with open(playbook_file, 'w', encoding='utf-8') as f:
            f.write(f"# Exploit Playbook for {agent_output.cve_id}\n")
            f.write(agent_output.exploit_playbook)

        # 保存执行日志
        log_file = self.output_dir / f"{agent_output.cve_id}_execution.log"
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"# Execution Log for {agent_output.cve_id}\n")
            for log_entry in agent_output.execution_log:
                f.write(f"{log_entry}\n")

        print(f"✅ 输出文件已保存:")
        print(f"   - {config_file}")
        print(f"   - {playbook_file}")
        print(f"   - {log_file}")

    def cleanup(self):
        """清理资源"""
        print("🧹 清理Pipeline资源...")

        # 停止Agent容器
        self.agent.stop_agent_container()

        # 清理CVE容器
        self.cve_manager.cleanup_all_containers()

        print("✅ Pipeline清理完成")
