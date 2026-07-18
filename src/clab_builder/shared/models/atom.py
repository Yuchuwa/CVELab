"""Atom 数据模型 — atom.yaml v2 结构化 Schema

定义 CVE atom 的完整元数据，供 Phase 1 (atomizer) 生成和 Phase 2 (orchestrator) 消费。
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, model_validator
from pathlib import Path

from clab_builder.shared.models.exploit_guide import ExploitGuideRef


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


class CapabilityType(str, Enum):
    EXECUTE_COMMAND = "execute_command"
    READ_FILE = "read_file"
    NETWORK_VANTAGE = "network_vantage"
    READ_CREDENTIAL = "read_credential"
    AUTHENTICATE = "authenticate"
    WRITE_FILE = "write_file"


class EvidenceLevel(str, Enum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    DECLARED = "declared"


class ExploitAccess(BaseModel):
    attack_vector: str = "network"
    privileges_required: str = "none"
    required_service: Dict[str, Any] = Field(default_factory=dict)


class CapabilityGrant(BaseModel):
    type: CapabilityType
    principal: str = "service_user"
    evidence_level: EvidenceLevel = EvidenceLevel.INFERRED
    evidence_ref: str = ""


class CapabilityExecutor(BaseModel):
    """Legacy command-channel metadata retained for compatibility.

    Guided Range consumes the descriptive ``exploit_guide`` command channel.  It
    does not mechanically substitute ``command_template`` into a downstream
    command.  Existing SysField/exporter consumers may continue to read this
    field during the migration period.
    """
    mode: str = "stateless"  # stateless | session
    command_template: str = ""  # 必须含 {{command}} 或 {{command_b64}}
    shell: str = "/bin/sh"
    verified: bool = False  # 是否真实验证过可执行任意命令
    # webshell 类通道需要先利用漏洞写入 webshell，再通过 HTTP 反复调用。
    # established_by 标注建立通道的 playbook step id（需先完成这些步骤）。
    established_by: List[str] = Field(default_factory=list)


class RuntimeBuildSpec(BaseModel):
    """Describes the derived runtime image build (batch 11).

    The runtime layer adds base tools on top of the original image WITHOUT
    modifying source_bundle. This record makes the build reproducible and
    traceable. Range materializes runtime_image (or falls back to
    docker_image) per docs/ATOM_RUNTIME_TO_RANGE_HANDOFF.md.
    """
    context: str = "runtime"
    dockerfile: str = "runtime/Dockerfile"
    install_script: str = "runtime/install-tools.sh"
    base_image_digest: str = ""
    generated_hash: str = ""
    # For custom-Dockerfile atoms: the intermediate image the runtime
    # Dockerfile FROMs (built from source_dockerfile), and the source
    # Dockerfile path. Empty for image-only atoms. Lets a future Range
    # rebuild reproduce the full two-stage build.
    intermediate_image: str = ""
    source_dockerfile: str = ""


class RuntimeStatus(str, Enum):
    NOT_REQUESTED = "not_requested"
    PENDING = "pending"
    READY = "ready"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


class RuntimeSpec(BaseModel):
    ports: List[int] = Field(default_factory=list)
    services: List[Any] = Field(default_factory=list)
    command: Optional[str] = None
    entrypoint: Optional[str] = None
    environment: Dict[str, str] = Field(default_factory=dict)
    # Original image; alias of docker_image. Empty on legacy atoms.
    source_image: Optional[str] = None
    # Derived image with base tools installed. Empty -> Range falls back to
    # docker_image / source_image.
    runtime_image: Optional[str] = None
    tool_profile: Optional[str] = None
    tool_profile_version: Optional[str] = None
    runtime_build: Optional[RuntimeBuildSpec] = None
    runtime_status: RuntimeStatus = RuntimeStatus.NOT_REQUESTED
    runtime_failure_reason: str = ""
    # Canonical runtime service classification used by Range/template
    # compatibility.  It is derived from the target runtime, not an Agent
    # claim and does not affect native-verification eligibility.
    service_family: Optional[str] = None
    # Original container user to restore after installing tools as root.
    # Empty/None = leave the base image default (which the FROM already
    # restored unless we override with USER root).
    user: Optional[str] = None


class FlagSpec(BaseModel):
    primary_path: str = "/flag.txt"
    injection: Dict[str, Any] = Field(default_factory=dict)


class ProbeType(str, Enum):
    CONTAINER_STATE = "container_state"
    TCP = "tcp"
    HTTP = "http"


class ReadinessProbe(BaseModel):
    probe_type: ProbeType = ProbeType.CONTAINER_STATE
    target: str = ""
    command: Optional[str] = None


class ValidationSpec(BaseModel):
    readiness: List[ReadinessProbe] = Field(
        default_factory=lambda: [ReadinessProbe()]
    )
    native: Dict[str, Any] = Field(default_factory=dict)
    orchestrated: Dict[str, Any] = Field(default_factory=dict)


class MaterialRole(str, Enum):
    """Role of a source-bundle file for downstream Range/agent consumption.

    - runtime:         compose/dockerfile/entrypoint — rebuild the target, never agent-visible
    - verification:    test_func.py, test logs — native/poc verifier evidence, never agent-visible
    - exploit_reference: test_vuln.py — a working exploit reference; agent-visible only under
                       an assisted exposure profile
    - exploit_material: payload/key/image the guide declares as required — agent-visible
    - solution:        solution.sh — full writeup, private by default
    """

    RUNTIME = "runtime"
    VERIFICATION = "verification"
    EXPLOIT_REFERENCE = "exploit_reference"
    EXPLOIT_MATERIAL = "exploit_material"
    SOLUTION = "solution"


class MaterialVisibility(str, Enum):
    """Default exposure of a material across agent exposure profiles.

    - assisted: visible only under the poc_assisted profile (test_vuln.py style)
    - always:   visible under every profile (guide-declared exploit material)
    - private:  never visible to the agent (runtime/verification/solution)
    """

    ASSISTED = "assisted"
    ALWAYS = "always"
    PRIVATE = "private"


class MaterialMetadata(BaseModel):
    role: MaterialRole = MaterialRole.EXPLOIT_REFERENCE
    visibility: MaterialVisibility = MaterialVisibility.ASSISTED


class SourceBundle(BaseModel):
    compose_file: Optional[str] = None
    readme_file: Optional[str] = None
    dockerfiles: List[str] = Field(default_factory=list)
    init_files: List[str] = Field(default_factory=list)
    poc_materials: List[str] = Field(default_factory=list)
    hashes: Dict[str, str] = Field(default_factory=dict)
    # Per-file role/visibility. Backward compatible: atoms without this field
    # keep the legacy semantics where every poc_material is treated as an
    # always-visible exploit material.
    material_metadata: Dict[str, MaterialMetadata] = Field(default_factory=dict)


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


class ChainRequires(BaseModel):
    """攻击链前置条件（由 atomizer 归纳，scenario 阶段消费）"""
    ports: List[int] = Field(default_factory=list)
    auth: str = "none"  # none | default | required | unknown
    callback: bool = False
    internet: bool = False


class ChainGrants(BaseModel):
    """漏洞成功利用后的能力结果"""
    command_execution: bool = False
    file_read: bool = False
    outbound_network: bool = False
    flag_capture: bool = False


class ChainContract(BaseModel):
    """轻量链路能力合同。roles 为派生缓存，requires/grants 才是事实来源。"""
    requires: ChainRequires = Field(default_factory=ChainRequires)
    grants: ChainGrants = Field(default_factory=ChainGrants)
    relay_compatible: bool = False
    roles: List[str] = Field(default_factory=list)
    classifier_version: str = "chain-contract-v1"


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
    runtime_spec: Optional[RuntimeSpec] = None
    source_bundle: Optional[SourceBundle] = None

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
    flag_spec: Optional[FlagSpec] = None

    exploit_access: ExploitAccess = Field(default_factory=ExploitAccess)
    capability_grants: List[CapabilityGrant] = Field(default_factory=list)
    capability_executors: Dict[str, CapabilityExecutor] = Field(default_factory=dict)
    exploit_guide: Optional[ExploitGuideRef] = None
    verification: Dict[str, Any] = Field(default_factory=dict)
    validation_spec: Optional[ValidationSpec] = None

    # 服务启动
    service_startup: ServiceStartup = Field(default_factory=ServiceStartup)

    # 攻陷后的 pivot / 横向移动能力
    post_exploit: PostExploit = Field(default_factory=PostExploit)

    # 复杂拓扑/攻击链编排合同
    chain_contract: ChainContract = Field(default_factory=ChainContract)

    # 验证状态
    verified: bool = False
    requirements: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)
    llm_check: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""
    source: str = ""

    @model_validator(mode="after")
    def _normalize_contract(self):
        if self.runtime_spec is None:
            self.runtime_spec = RuntimeSpec(ports=list(self.ports), services=list(self.services))
        if self.flag_spec is None:
            path = self.flag_injection.file_path or "/flag.txt"
            self.flag_spec = FlagSpec(primary_path=path, injection=self.flag_injection.model_dump(mode="json"))
        if self.validation_spec is None:
            self.validation_spec = ValidationSpec()
        if self.version >= 3 and self.verified:
            native = self.verification.get("native_verification", {})
            # verified reflects the native agent result (exploit reproduced +
            # flag matched). Orchestrated environment rebuild is a separate
            # environment-correctness check tracked via environment_ready;
            # its failure no longer downgrades verified, so a successful
            # native exploit is not erased by a transient compose-rebuild
            # issue. Template-anchor eligibility is decided separately.
            if native.get("success") is not True:
                self.verified = False
        return self

    @property
    def is_legacy(self) -> bool:
        return self.version < 3

    @property
    def verified_capability_types(self) -> set[CapabilityType]:
        if self.capability_grants:
            return {
                grant.type for grant in self.capability_grants
                if grant.evidence_level == EvidenceLevel.VERIFIED
            }
        mapping = {
            PivotCapability.NONE: set(),
            PivotCapability.CREDENTIAL: {CapabilityType.READ_CREDENTIAL},
            PivotCapability.PORT_FORWARD: {CapabilityType.NETWORK_VANTAGE},
            PivotCapability.SHELL: {CapabilityType.EXECUTE_COMMAND, CapabilityType.NETWORK_VANTAGE},
            PivotCapability.FULL_TOOLBOX: {
                CapabilityType.EXECUTE_COMMAND, CapabilityType.NETWORK_VANTAGE,
                CapabilityType.READ_FILE,
            },
        }
        return mapping.get(self.post_exploit.pivot_capability, set())

    def has_verified_capability(self, capability: CapabilityType) -> bool:
        return capability in self.verified_capability_types
