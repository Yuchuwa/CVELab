"""Template Loader — 加载拓扑模板目录"""

import yaml
from pathlib import Path
from typing import Optional

from clab_builder.shared.models.template import TopologyTemplate


class TemplateLoader:
    """从 templates/ 目录加载拓扑模板"""

    def __init__(self, templates_dir: str = "templates"):
        self.templates_dir = Path(templates_dir)

    def load(self, name: str) -> TopologyTemplate:
        """加载指定模板

        Args:
            name: 模板目录名 (e.g. "dmz_simple")

        Returns:
            TopologyTemplate 实例

        Raises:
            FileNotFoundError: 模板目录或文件不存在
            ValueError: 模板 YAML 格式错误
        """
        tpl_dir = self.templates_dir / name
        if not tpl_dir.is_dir():
            raise FileNotFoundError(f"Template not found: {tpl_dir}")

        template_yaml = tpl_dir / "template.yaml"
        if not template_yaml.exists():
            raise FileNotFoundError(f"template.yaml not found in {tpl_dir}")

        clab_yaml = tpl_dir / "clab.yaml"
        if not clab_yaml.exists():
            raise FileNotFoundError(f"clab.yaml not found in {tpl_dir}")

        # 解析 template.yaml
        data = yaml.safe_load(template_yaml.read_text())
        try:
            template = TopologyTemplate(**data)
        except Exception as e:
            raise ValueError(f"Invalid template.yaml in {tpl_dir}: {e}") from e

        return template

    def load_clab_base(self, name: str) -> dict:
        """加载模板的基础 CLab YAML（返回原始 dict）"""
        clab_yaml = self.templates_dir / name / "clab.yaml"
        return yaml.safe_load(clab_yaml.read_text())

    def load_ansible_base(self, name: str) -> str:
        """加载模板的基础 Ansible playbook 内容"""
        ansible_path = self.templates_dir / name / "ansible" / "base.yaml"
        if ansible_path.exists():
            return ansible_path.read_text()
        return ""

    def list_available(self) -> list[str]:
        """列出所有可用模板"""
        templates = []
        if not self.templates_dir.exists():
            return templates
        for d in sorted(self.templates_dir.iterdir()):
            if d.is_dir() and (d / "template.yaml").exists():
                templates.append(d.name)
        return templates
