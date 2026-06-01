"""主入口点 - 用于 clab-builder 命令"""
import sys
from .core import ContainerLabParser, EnvironmentValidator
from .core.generator import TopologyGenerator


def main():
    """主入口点"""
    if len(sys.argv) < 2:
        print("Clab Builder - ContainerLab拓扑生成和验证工具")
        print("")
        print("使用方法:")
        print("  python -m packages.clab_builder parse <yaml_file>")
        print("  python -m packages.clab_builder validate <lab_name>")
        print("  python -m packages.clab_builder generate <yaml_file>")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'parse':
        if len(sys.argv) < 3:
            print("使用方法: python -m packages.clab_builder parse <yaml_file>")
            sys.exit(1)
        parse_command(sys.argv[2])
    elif command == 'validate':
        if len(sys.argv) < 3:
            print("使用方法: python -m packages.clab_builder validate <lab_name>")
            sys.exit(1)
        validate_command(sys.argv[2])
    elif command == 'generate':
        if len(sys.argv) < 3:
            print("使用方法: python -m packages.clab_builder generate <yaml_file>")
            sys.exit(1)
        generate_command(sys.argv[2])
    else:
        print(f"未知命令: {command}")
        sys.exit(1)


def parse_command(yaml_file: str):
    """解析ContainerLab YAML文件"""
    print(f"📄 解析文件: {yaml_file}")
    parser = ContainerLabParser(yaml_file)
    topology = parser.extract_topology_specification()

    print(f"✅ 解析成功!")
    print(f"   实验室名称: {topology.lab_name}")
    print(f"   节点数量: {len(topology.nodes)}")
    print(f"   链接数量: {len(topology.links)}")
    cve_nodes = [n.name for n in topology.nodes if n.cve_injection]
    print(f"   有CVE的节点: {cve_nodes if cve_nodes else '无'}")


def validate_command(lab_name: str):
    """验证已部署的实验室环境"""
    print(f"🔍 验证实验室: {lab_name}")
    validator = EnvironmentValidator(lab_name)
    result = validator.validate_all()

    print(f"✅ 验证完成!")
    print(f"   总分: {result.total_score:.1f}/100")
    print(f"   语法验证: {result.syntax_score:.1f}/20")
    print(f"   部署验证: {result.deployment_score:.1f}/30")
    print(f"   容器验证: {result.container_score:.1f}/20")
    print(f"   网络验证: {result.network_score:.1f}/15")
    print(f"   CVE验证: {result.cve_score:.1f}/15")


def generate_command(yaml_file: str):
    """生成拓扑配置"""
    print(f"🏗️  生成拓扑: {yaml_file}")
    generator = TopologyGenerator(yaml_file)
    clab_config, ansible_config = generator.generate()

    print(f"✅ 生成完成!")
    print(f"   生成了ContainerLab和Ansible配置")


if __name__ == '__main__':
    main()