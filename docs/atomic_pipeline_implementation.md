# CVE原子化Pipeline实现详解

## 🎯 整体流程概览

```
用户定义 → 数据收集 → 阶段映射 → 质量验证 → Catalog存储
    ↓          ↓          ↓          ↓          ↓
  CVE列表   NVD+VulnHub  ATT&CK    评分系统   YAML文件
```

---

## 📦 核心数据结构

### 1. Catalog数据结构 (`catalog.py`)

#### 🔹 **CVECatalog** - 完整的CVE原子化信息
```python
@dataclass
class CVECatalog:
    basic_info: BasicInfo              # CVE基础信息
    environment: EnvironmentInfo      # 环境需求
    attack_info: AttackInfo           # 攻击方法
    attack_chain: AttackChainFit      # ATT&CK适配
    topology_fit: TopologyFit        # 拓扑适配
    verification: VerificationStatus  # 测试状态
    catalog_version: str = "1.0"
    last_updated: str = ""
    source_reliability: str = "medium"
```

#### 🔹 **BasicInfo** - 基础信息（可从NVD自动获取）
```python
@dataclass
class BasicInfo:
    cve_id: str                      # CVE-2021-44228
    name: str                        # Log4j Remote Code Execution
    cvss_score: float                # 7.5 (0-10)
    description: str                 # 漏洞描述
    publish_date: str                # 发布日期
    attack_vector: str               # NETWORK/LOCAL/ADJACENT
    attack_complexity: str           # LOW/MEDIUM/HIGH
```

#### 🔹 **EnvironmentInfo** - 环境信息（从VulnHub提取）
```python
@dataclass
class EnvironmentInfo:
    docker_image: str                # vulhub/log4j:latest
    image_source: str                # Docker Hub URL
    required_ports: List[int]        # [8080, 8443]
    estimated_memory: int            # 1024 MB
    startup_time: int                # 30 seconds
    os_type: str                     # linux
```

#### 🔹 **AttackChainFit** - MITRE ATT&CK适配度
```python
@dataclass
class AttackChainFit:
    primary_stage: MITREAttackStage  # 主要攻击阶段
    stage_scores: Dict[str, float]   # 各阶段评分 (0-1)
    reasoning: str                    # 适配理由
    confidence: float                 # 置信度 (0-1)
```

---

## 🔄 实际处理流程

### 阶段1: 数据收集 (`processor.py`)

#### 📍 **当前实现**: 模拟数据处理
```python
class CVEProcessor:
    def process_from_vulnhub(self, vulnhub_url: str):
        # 1. 获取VulnHub README (目前是模拟数据)
        readme_content = self._fetch_vulnhub_readme(vulnhub_url)

        # 2. 提取CVE ID (使用正则表达式)
        cve_id = self._extract_cve_id(readme_content)

        # 3. 查询NVD数据库 (目前是模拟数据)
        nvd_info = self._query_nvd_database(cve_id)

        # 4. 构建catalog数据
        catalog_data = {
            "basic_info": {...},
            "environment": self._extract_environment_info(readme_content),
            "attack_info": self._extract_attack_info(readme_content),
            "attack_chain": {},  # 稍后填充
            "topology_fit": {},  # 稍后填充
            "verification": {...}
        }

        return catalog_data
```

#### 🔹 **环境信息提取逻辑**:
```python
def _extract_environment_info(self, readme_content: str):
    # 提取Docker镜像 (正则匹配)
    docker_matches = re.findall(r'vulhub/[\w\-]+(?:\:[\w\.]+)?', readme_content)
    docker_image = docker_matches[0] if docker_matches else "vulhub/unknown:latest"

    # 提取端口 (智能识别多种格式)
    port_patterns = [
        r'(?:ports?|端口)[:\s]*(?:[\d,]+\s*)+',  # "Ports: 8080, 8443"
        r'-p\s*(?:\d+:\d+)',                       # Docker -p format
        r'--publish\s+\d+'                         # Docker --publish format
    ]

    ports = []
    for pattern in port_patterns:
        match = re.search(pattern, readme_content, re.IGNORECASE)
        if match:
            numbers = re.findall(r'\b(\d{2,5})\b', match.group())
            for num in numbers:
                port_num = int(num)
                if 10 < port_num < 65536:  # 有效端口范围
                    ports.append(port_num)

    return {
        'docker_image': docker_image,
        'required_ports': ports,
        'estimated_memory': 1024,
        'startup_time': 30,
        'os_type': 'linux'
    }
```

#### 🔹 **攻击信息生成逻辑**:
```python
def _generate_attack_info(self, cve_info, basic_info):
    name_lower = cve_info['name'].lower()

    # 根据CVE名称推断攻击方法
    if 'privilege' in name_lower or 'escalation' in name_lower:
        return {
            'exploit_method': 'Privilege Escalation',
            'attack_surface': 'Local',
            'access_required': 'local',
            'complexity': 'low',
            'popular': True,
            'exploit_available': True
        }
    elif 'sql' in name_lower:
        return {
            'exploit_method': 'SQL Injection',
            'attack_surface': 'HTTP',
            'access_required': 'network',
            'complexity': 'low',
            'popular': True,
            'exploit_available': True
        }
    # ... 其他类型的攻击信息
```

---

### 阶段2: ATT&CK阶段映射 (`mapper.py`)

#### 📍 **核心算法**: 多因素评分系统

```python
class AttackStageMapper:
    def map_from_description(self, cve_description, cvss_vector):
        stage_scores = {stage.value: 0.0 for stage in MITREAttackStage}

        # 1. 关键词匹配评分
        for stage, keywords in self.stage_keywords.items():
            for keyword in keywords:
                if keyword.lower() in combined_text:
                    stage_scores[stage.value] += 0.3

        # 2. 启发式规则评分
        heuristics = {
            "remote code execution": [INITIAL_ACCESS, EXECUTION, LATERAL_MOVEMENT],
            "sql injection": [INITIAL_ACCESS, EXECUTION],
            "authentication bypass": [CREDENTIAL_ACCESS, INITIAL_ACCESS]
        }

        for pattern, applicable_stages in self.heuristics.items():
            if pattern in cve_description.lower():
                for stage in applicable_stages:
                    stage_scores[stage.value] += 0.4

        # 3. CVSS向量评分
        if "AV:N" in cvss_vector:  # Network attack vector
            stage_scores[INITIAL_ACCESS.value] += 0.2
        if "AV:L" in cvss_vector:  # Local attack vector
            stage_scores[LATERAL_MOVEMENT.value] += 0.2

        # 4. 分数标准化 (0-1范围)
        for stage in stage_scores:
            stage_scores[stage] = min(stage_scores[stage], 1.0)

        # 5. 确定主要阶段
        primary_stage = self._determine_primary_stage(stage_scores)

        return AttackChainFit(
            primary_stage=primary_stage,
            stage_scores=stage_scores,
            reasoning=self._generate_reasoning(stage_scores),
            confidence=max(stage_scores.values())
        )
```

#### 🔹 **关键词映射系统**:
```python
stage_keywords = {
    INITIAL_ACCESS: [
        "entry point", "initial access", "remote exploit", "remote",
        "网络入口", "初始访问"
    ],
    EXECUTION: [
        "code execution", "rce", "remote code execution",
        "execute", "代码执行"
    ],
    PRIVILEGE_ESCALATION: [
        "privilege escalation", "escalate", "privilege",
        "权限提升", "提权"
    ],
    DEFENSE_EVASION: [
        "defense evasion", "bypass", "avoid detection",
        "防御规避", "绕过检测"
    ],
    CREDENTIAL_ACCESS: [
        "credential", "password", "authentication",
        "凭证", "密码"
    ]
    # ... 其他12个MITRE ATT&CK阶段
}
```

---

### 阶段3: 质量验证 (`validator.py`)

#### 📍 **三级验证体系**:

```python
class CVEAtomicValidator:
    def validate_catalog_syntax(self, catalog_data):
        """语法验证"""
        issues = []

        # 检查必需字段
        required_sections = ['basic_info', 'environment', 'attack_info',
                          'attack_chain', 'topology_fit', 'verification']

        # 检查基础信息完整性
        basic_fields = ['cve_id', 'name', 'cvss_score', 'description']

        # 检查环境信息完整性
        if not catalog_data['environment']['docker_image']:
            issues.append("environment.docker_image 为空")

        return len(issues) == 0, issues

    def validate_logic_consistency(self, catalog_data):
        """逻辑一致性验证"""
        issues = []

        # CVSS分数范围检查 (0-10)
        cvss_score = catalog_data.get('basic_info', {}).get('cvss_score', 0)
        if not 0 <= cvss_score <= 10:
            issues.append(f"CVSS分数超出范围: {cvss_score}")

        # 端口号合理性检查 (1-65535)
        ports = catalog_data.get('environment', {}).get('required_ports', [])
        invalid_ports = [p for p in ports if not 1 <= p <= 65535]

        # 攻击链分数范围检查 (0-1)
        stage_scores = catalog_data.get('attack_chain', {}).get('stage_scores', {})
        for stage, score in stage_scores.items():
            if not 0 <= score <= 1:
                issues.append(f"attack_chain.{stage} 分数超出范围: {score}")

        return len(issues) == 0, issues
```

#### 🔹 **质量评分系统** (`validator.py` 中的CVEQualityScorer):
```python
class CVEQualityScorer:
    def score_catalog(self, catalog_data):
        """综合质量评分 (0-1)"""
        scores = {
            'completeness': self._score_completeness(catalog_data),  # 完整性
            'accuracy': self._score_accuracy(catalog_data),          # 准确性
            'exploitability': self._score_exploitability(catalog_data) # 可利用性
        }

        # 加权平均
        weights = {'completeness': 0.3, 'accuracy': 0.4, 'exploitability': 0.3}
        total_score = sum(scores[key] * weights[key] for key in scores)

        return {
            'scores': scores,
            'total_score': total_score,
            'quality_level': self._determine_quality_level(total_score)
        }

    def _score_completeness(self, catalog_data):
        """完整性评分: 检查必需字段的填充情况"""
        required_fields = [...]  # 所有必需字段
        filled_fields = sum(1 for field in required_fields if catalog_data.get(field))
        return filled_fields / len(required_fields)

    def _score_accuracy(self, catalog_data):
        """准确性评分: 检查数据的逻辑一致性"""
        # CVSS分数合理性
        # 端口号合理性
        # Docker镜像格式正确性
        return self._check_data_accuracy(catalog_data)

    def _score_exploitability(self, catalog_data):
        """可利用性评分: 检查攻击可行性"""
        attack_info = catalog_data.get('attack_info', {})

        # 公开可用性 (+0.3)
        # 攻击复杂度 (+0.2)
        # 网络可达性 (+0.3)
        # 依赖服务可用性 (+0.2)
        return self._calculate_exploitability(attack_info)
```

---

## 🛠️ 批量收集实现 (`collect_modern_cves.py`)

### 📍 **收集流程**:

```python
class ModernCVECollector:
    def collect_all_cves(self):
        for cve_info in self.target_cves:  # 32个现代CVE
            # 1. 查询NVD获取真实数据
            basic_info = self._query_nvd_api(cve_id)
            if not basic_info:
                basic_info = self._generate_mock_basic_info(cve_info)

            # 2. 生成环境信息
            env_info = self._generate_env_info(cve_info)

            # 3. 生成攻击信息
            attack_info = self._generate_attack_info(cve_info, basic_info)

            # 4. 使用mapper映射ATT&CK阶段
            attack_chain = self._map_attack_chain(basic_info, attack_info)

            # 5. 生成拓扑适配信息
            topology_fit = self._generate_topology_fit(env_info, attack_info)

            # 6. 组装完整catalog
            catalog = {
                "basic_info": basic_info,
                "environment": env_info,
                "attack_info": attack_info,
                "attack_chain": attack_chain,
                "topology_fit": topology_fit,
                "verification": {...},
                "last_updated": datetime.now().isoformat()
            }

            # 7. 验证catalog质量
            is_valid, issues = self.validator.validate_catalog_syntax(catalog)
            if not is_valid:
                continue  # 跳过无效catalog

            quality_score = self.scorer.score_catalog(catalog)
            if quality_score['total_score'] < 0.6:
                continue  # 跳过低质量catalog

            # 8. 保存catalog
            self._save_catalog(cve_id, catalog)
```

### 🔹 **NVD API集成**:
```python
def _query_nvd_api(self, cve_id):
    """查询NVD API获取真实CVE数据"""
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'cveId': cve_id}

        response = requests.get(url, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if data.get('totalResults', 0) > 0:
                cve_item = data['vulnerabilities'][0]['cve']

                # 提取CVSS分数
                cvss_data = cve_item['metrics'].get('cvssMetricV31', [{}])[0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)

                # 提取描述
                for desc in cve_item.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                return {
                    'cve_id': cve_id,
                    'name': description[:50],  # 前50字符
                    'cvss_score': cvss_score,
                    'description': description,
                    'publish_date': cve_item.get('published', ''),
                    'attack_vector': self._extract_cvss_field(cve_item, 'attackVector'),
                    'attack_complexity': self._extract_cvss_field(cve_item, 'attackComplexity')
                }

    except Exception as e:
        return None  # API失败返回None，使用模拟数据
```

---

## 📊 当前数据处理状态

### ✅ **已实现**:
1. **数据结构定义** - 6个核心dataclass
2. **ATT&CK映射算法** - 12个阶段，多因素评分
3. **质量验证系统** - 语法、逻辑、利用性三级验证
4. **批量收集工具** - 自动化处理32个现代CVE

### ⚠️ **当前限制**:
1. **VulnHub数据获取** - 目前使用模拟数据，未实际爬取
2. **NVD API限制** - API请求频率限制，部分CVE数据缺失
3. **攻击信息推断** - 基于名称简单推断，未深度分析writeups
4. **拓扑适配** - 静态规则，缺乏智能匹配

### 🔧 **可优化方向**:
1. **真实VulnHub爬取** - 实际获取README内容
2. **Writeup分析** - 使用NLP提取详细攻击步骤
3. **环境测试** - 实际运行Docker容器验证
4. **机器学习** - 训练ATT&CK映射模型

---

## 🎯 实际数据流示例

### **输入**:
```yaml
CVE信息:
  cve_id: CVE-2021-44228
  name: Log4j Remote Code Execution
  vulnhub_url: https://github.com/vulnhub/vulhub/tree/master/log4j
```

### **处理过程**:
```python
# 1. NVD查询 → 基础信息
basic_info = {
    'cvss_score': 7.5,
    'description': 'Apache Log4j2 JNDI features...',
    'attack_vector': 'NETWORK',
    'attack_complexity': 'LOW'
}

# 2. VulnHub分析 → 环境信息
environment = {
    'docker_image': 'vulhub/log4j:latest',
    'required_ports': [8080],
    'estimated_memory': 1024
}

# 3. ATT&CK映射 → 攻击链
attack_chain = {
    'primary_stage': 'execution',
    'stage_scores': {
        'initial_access': 0.9,
        'execution': 1.0,
        'lateral_movement': 0.4
    }
}

# 4. 质量验证 → 质量分数
quality_score = 0.96  # 高质量catalog
```

### **输出**:
```yaml
# data/catalogs/verified/CVE-2021-44228.yaml
basic_info:
  cve_id: CVE-2021-44228
  cvss_score: 7.5
  description: Log4j Remote Code Execution vulnerability
environment:
  docker_image: vulhub/log4j:latest
  required_ports: [8080]
attack_chain:
  primary_stage: execution
  stage_scores:
    initial_access: 0.9
    execution: 1.0
```

---

## 🚀 下一步优化方向

### **优先级1: 数据质量提升**
- 实现真实VulnHub爬取
- 增强NVD API错误处理
- 添加Writeup深度分析

### **优先级2: 算法优化**
- 改进ATT&CK映射准确度
- 添加拓扑适配智能匹配
- 实现环境需求动态计算

### **优先级3: 验证增强**
- 实际Docker容器测试
- 攻击可复现性验证
- 自动化质量反馈