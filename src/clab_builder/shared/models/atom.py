"""Atom 数据模型 — atom.yaml v2 结构化 Schema

定义 CVE atom 的完整元数据，供 Phase 1 (atomizer) 生成和 Phase 2 (orchestrator) 消费。
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from pathlib import Path


# ── 枚举类型 ──────────────────────────────────────────

class VulnCategory(str, Enum):
    """漏洞类别 — CVE Matcher 用"""
    RCE = "RCE"
    LFI = "LFI"
    RFI = "RFI"
    SSRF = "SSRF"
    DESERIALIZATION = "Deserialization"
    LPE = "LPE"
    AUTH_BYPASS = "Auth_Bypass"
    INFO_LEAK = "Info_Leak"
    INJECTION = "Injection"
    PARSING = "Parsing"


class MitrePhase(str, Enum):
    """MITRE ATT&CK 阶段"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ServiceRole(str, Enum):
    """服务角色 — 模板 zone 匹配用"""
    WEB_APPLICATION = "web_application"
    MIDDLEWARE = "middleware"
    DATABASE = "database"
    FILE_SERVICE = "file_service"
    SYSTEM_SERVICE = "system_service"
    FRAMEWORK = "framework"


class ExploitComplexity(str, Enum):
    """攻击复杂度 — Agent 策略选择"""
    SIMPLE = "simple"          # 单条命令
    MEDIUM = "medium"          # 多步骤, 无需额外工具
    COMPLEX = "complex"        # 需要下载/编译工具


class AttackMethod(str, Enum):
    """攻击方式 — Agent 执行策略"""
    SINGLE_REQUEST = "single_request"
    MULTI_STEP_HTTP = "multi_step_http"
    SSH_EXPLOIT = "ssh_exploit"
    SERVICE_PROTOCOL = "service_protocol"
    REVERSE_CALLBACK = "reverse_callback"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"


class FlagMethod(str, Enum):
    """FLAG 注入方式"""
    ENV_VAR = "env_var"
    FILE = "file"
    DATABASE = "database"
    REDIS_KEY = "redis_key"
    HTTP_HEADER = "http_header"


class CallbackType(str, Enum):
    """回调类型"""
    NONE = "none"
    LDAP = "LDAP"
    HTTP = "HTTP"
    TCP = "TCP"
    SSH = "SSH"


class PivotCapability(str, Enum):
    """攻陷后可作为中间节点的能力"""
    NONE = "none"
    CREDENTIAL = "credential"
    PORT_FORWARD = "port_forward"
    SHELL = "shell"
    FULL_TOOLBOX = "full_toolbox"


# ── 子模型 ──────────────────────────────────────────

class ServiceInfo(BaseModel):
    """atom 中的服务信息"""
    name: str
    image: str
    is_target: bool = True


class NetworkRequirements(BaseModel):
    """网络需求"""
    needs_callback: bool = False
    callback_type: CallbackType = CallbackType.NONE
    needs_ssh: bool = False
    needs_tool_download: bool = False


class DefaultCredentials(BaseModel):
    """默认凭据"""
    username: Optional[str] = None
    password: Optional[str] = None


class FlagInjection(BaseModel):
    """FLAG 注入配置"""
    method: FlagMethod = FlagMethod.ENV_VAR
    env_var_name: str = "FLAG"
    file_path: Optional[str] = None       # method=file
    db_type: Optional[str] = None         # method=database
    db_query: Optional[str] = None        # method=database
    redis_key: Optional[str] = None       # method=redis_key


class InitFileMapping(BaseModel):
    """初始化文件映射 — container_path -> init/ 中的文件名"""
    container_path: str
    filename: str
    is_directory: bool = False


class ServiceStartup(BaseModel):
    """服务启动配置 — 从 deploy.yaml 提取"""
    wait_seconds: int = 10
    health_check: Optional[str] = None
    init_tasks: List[str] = Field(default_factory=list)
    init_files: List[InitFileMapping] = Field(default_factory=list)


class PostExploit(BaseModel):
    """漏洞利用后的横向移动能力"""
    pivot_capability: PivotCapability = PivotCapability.NONE
    requires_pivot_host: bool = False
    pivot_host_image: str = "cvelab-pivot-base:latest"


# ── 主模型 ──────────────────────────────────────────

class AtomConfig(BaseModel):
    """atom.yaml v2 完整模型

    Phase 1 (atomizer) 生成，Phase 2 (orchestrator) 消费。
    """
    # 基本信息
    cve_id: str
    category: str
    description: str = ""
    version: int = Field(default=2, description="schema 版本")

    # 容器配置
    docker_image: str
    ports: List[int] = Field(default_factory=list)
    services: List[ServiceInfo] = Field(default_factory=list)

    # 漏洞分类
    vuln_category: VulnCategory
    primary_mitre_phase: MitrePhase
    mitre_mapping: Dict[str, List[str]] = Field(default_factory=dict)

    # 服务角色
    service_role: ServiceRole

    # 攻击信息
    exploit_complexity: ExploitComplexity
    attack_method: AttackMethod
    vulnerability_type: str = ""  # 保留原始自由文本，向后兼容

    # 网络需求
    network_requirements: NetworkRequirements = Field(default_factory=NetworkRequirements)

    # 认证信息
    default_credentials: Optional[DefaultCredentials] = None

    # FLAG
    flag_injection: FlagInjection = Field(default_factory=FlagInjection)
    flag_verify_command: str = ""
    flag_value: Optional[str] = None  # ground-truth flag injected at atomization time

    # 服务启动
    service_startup: ServiceStartup = Field(default_factory=ServiceStartup)

    # 攻陷后的 pivot / 横向移动能力
    post_exploit: PostExploit = Field(default_factory=PostExploit)

    # 验证状态
    verified: bool = False
    requirements: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)
    llm_check: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""
    source: str = ""
