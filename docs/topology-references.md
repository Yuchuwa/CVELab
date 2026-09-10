# 拓扑模板参考资料与设计背书

本文档说明每个网络拓扑模板对应的企业经典网络架构和安全模型来源，证明我们的模板是对真实企业网络拓扑和安全模型的抽象。

---

## 参考来源

### 1. MITRE ATT&CK 框架

MITRE ATT&CK 是全球最广泛使用的对抗战术与技术知识库，记录了真实 APT 组织和恶意软件使用的攻击技术。

- **Lateral Movement (TA0008)**: 横向移动战术，描述攻击者在网络内部从一个系统移动到另一个系统的技术
  - 来源: https://attack.mitre.org/tactics/TA0008/
- **Exploitation of Remote Services (T1210)**: 利用远程服务漏洞进行横向移动
  - 来源: https://attack.mitre.org/techniques/T1210/
  - 引用: "A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system."
- **Remote Services (T1021)**: 使用合法凭证通过 SSH/RDP/SMB 等协议远程登录
  - 来源: https://attack.mitre.org/techniques/T1021/
  - 引用: "servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network."
- **Network Service Discovery (T1046)**: 网络服务发现，攻击者扫描内部网络发现可利用的服务
  - 来源: https://attack.mitre.org/techniques/T1046/
- **Credentials from Password Stores (T1555)**: 从密码存储中获取凭证，用于横向移动
  - 来源: https://attack.mitre.org/techniques/T1555/
  - 引用: "Once credentials are obtained, they can be used to perform lateral movement and access restricted information."
- **Network Segmentation (M1030)**: 网络分段缓解措施
  - 来源: https://attack.mitre.org/mitigations/M1030/
  - 引用: "Segment networks and systems appropriately to reduce access to critical systems and services to controlled methods."

### 2. NIST 网络安全指南

- **NIST SP 800-94**: Guide to Intrusion Detection and Prevention Systems — 入侵检测与防御系统指南，涉及网络分段与 DMZ 部署中的入侵检测
- **NIST SP 800-207**: Zero Trust Architecture — 零信任架构，强调"永不信任，始终验证"和最小权限原则
- **NIST SP 800-61 Rev. 3**: Incident Response Recommendations and Considerations for Cybersecurity Risk Management — 事件响应中的网络隔离策略

### 3. 行业标准网络架构

以下架构模式来自 Cisco、Palo Alto Networks、Fortinet 等网络安全厂商的参考架构文档和企业安全最佳实践：

- **Defense in Depth (纵深防御)**: 多层安全控制，每层独立防御
- **DMZ (Demilitarized Zone)**: 隔离内外网的缓冲区
- **Zero Trust Network Access (ZTNA)**: 零信任网络访问，默认拒绝所有连接
- **Bastion Host / Jump Server**: 堡垒机/跳板机，唯一入口点
- **Microsegmentation (微分段)**: 将网络细分为更小的安全区域

---

## 模板与参考来源映射

### 1. dmz_simple — 单层 DMZ 直连

**对应架构**: 经典单层 DMZ 部署

**参考来源**:
- NIST SP 800-94: 入侵检测系统部署中的 DMZ 隔离区设计，放置对外服务
- MITRE ATT&CK M1030 (Network Segmentation): 基础网络分段

**设计依据**: 最基础的企业 DMZ 部署——对外服务的 Web 服务器放在 DMZ，防火墙隔离内外网。agent 需从外部攻入 DMZ 的目标服务。

---

### 2. dmz_dual — 单层双目标 DMZ

**对应架构**: 多服务 DMZ 部署

**参考来源**:
- NIST SP 800-94: DMZ 中可部署多个对外服务
- MITRE ATT&CK T1210 (Exploitation of Remote Services): 在同一网段内对多个服务进行横向移动

**设计依据**: 真实 DMZ 通常部署多个服务（Web + 邮件 + DNS），攻击者需连续攻破同一网段内的多个目标。

---

### 3. enterprise_3tier — 三层纵深防御

**对应架构**: 经典三层企业网络（DMZ → Application → Data）

**参考来源**:
- NIST SP 800-94: Defense in Depth 纵深防御模型
- MITRE ATT&CK TA0008 (Lateral Movement): 横向移动战术
- MITRE ATT&CK T1210 (Exploitation of Remote Services): "Servers are likely a high value target for lateral movement exploitation"
- MITRE ATT&CK M1030 (Network Segmentation): "Segment networks and systems appropriately to reduce access to critical systems"

**设计依据**: 最经典的企业三层网络架构——DMZ 放对外 Web 服务，App 层放内部应用，Data 层放核心数据库。每层之间用防火墙/路由器隔离，攻击者需逐层突破。这是 Cisco 和 Palo Alto Networks 参考架构中最基础的企业网络模型。

---

### 4. enterprise_4tier / enterprise_5tier — 多层纵深防御

**对应架构**: 多层企业网络（增加中间件层/工作站层）

**参考来源**:
- NIST SP 800-207 (Zero Trust Architecture): 多层分段实现零信任
- MITRE ATT&CK T1210: "An adversary may need to determine if the remote system is in a vulnerable state"
- MITRE ATT&CK T1021 (Remote Services): 使用远程服务进行横向移动

**设计依据**: 大型企业（如金融、政府）的网络通常 4-5 层深——DMZ → 应用层 → 中间件层（消息队列、API 网关）→ 内部工作站 → 核心数据。每增加一层，攻击者需要多攻破一个节点。对应 NIST 零信任架构中的多层分段原则。

---

### 5. enterprise_tree — 树形分叉网络

**对应架构**: 多业务分支企业网络

**参考来源**:
- MITRE ATT&CK T1046 (Network Service Discovery): "adversaries may attempt to get a listing of services running on remote hosts"
- MITRE ATT&CK T1210: "Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk"
- NIST SP 800-94: 多业务部门网络的分段隔离与入侵检测覆盖

**设计依据**: 大型企业通常有多个业务部门（如研发、运营、财务），每个部门有独立的网络分支。攻击者攻入边缘后，面临路径选择——去哪个分支？跨分支访问被防火墙禁止。这对应真实企业中的"部门级 VLAN 隔离"架构。

---

### 6. dual-dmz — 双 DMZ 网关

**对应架构**: 双层 DMZ + 网关过滤

**参考来源**:
- NIST SP 800-94: External DMZ + Internal DMZ 双层隔离中的入侵检测部署
- MITRE ATT&CK M1030 (Network Segmentation): "reduce access to critical systems and services to controlled methods"
- Cisco Reference Architecture: 双层防火墙 + 双 DMZ 设计

**设计依据**: 高安全要求的企业（如银行、政府）使用双层 DMZ——外部 DMZ 放对外服务，内部 DMZ 放受信中间件，中间用网关防火墙过滤。攻击者打穿外部 DMZ 后，不能直接到应用层，必须再过一道内部 DMZ。单向不可回退对应防火墙的"只允许前进，不允许后退"策略。

---

### 7. asymmetric-acl — 非对称访问控制

**对应架构**: 非对称防火墙规则

**参考来源**:
- MITRE ATT&CK T1021 (Remote Services): 反向连接（reverse shell）依赖网络双向可达
- MITRE ATT&CK T1555 (Credentials from Password Stores): "Once credentials are obtained, they can be used to perform lateral movement"
- NIST SP 800-94: 防火墙规则可以指定方向性（inbound/outbound），IDPS 可检测违规流量

**设计依据**: 真实企业防火墙规则通常不对称——某些区域可以到其他区域，但反过来不行。例如数据中心的数据库服务器可以接收应用层的连接，但不允许主动连接应用层（防止数据外泄）。攻击者使用反向 shell 时需要目标回连，在非对称 ACL 下会失败，必须改用正向连接（bind shell 或直接 RCE）。

---

### 8. multi-path — 多路径 + 蜜罐死路

**对应架构**: 蜜罐 + 路径分流

**参考来源**:
- MITRE ATT&CK T1046 (Network Service Discovery): 攻击者扫描网络发现服务
- NIST SP 800-94: Honeypot 部署作为入侵检测补充手段
- The DFIR Report (真实事件响应报告): Ryuk 事件中攻击者使用 AdFind、nltest、Nmap 等工具进行网络服务发现，展示了攻击者在真实环境中如何扫描并选择攻击路径
  - 来源: https://thedfirreport.com/2020/10/08/ryuks-return/
  - 来源: https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/

**设计依据**: 真实企业网络中部署蜜罐诱导攻击者走错路。攻击者扫描后发现容易打的服务（弱口令），打穿后发现是蜜罐（假 flag），浪费时间。必须能辨别真假路径。The DFIR Report 记录的 Ryuk 事件展示了攻击者在真实环境中使用 AdFind、nltest 等工具进行网络服务发现的模式——在多路径环境中，攻击者面临路径选择，可能误入蜜罐死路。

---

### 9. bastion — 堡垒机跳板

**对应架构**: Jump Server / Bastion Host 架构

**参考来源**:
- MITRE ATT&CK T1021 (Remote Services): "adversaries may use valid credentials to log into a service that accepts remote connections"
- MITRE ATT&CK M1035 (Limit Access to Resource Over Network): "Prevent unnecessary remote access to file shares, hypervisors, sensitive systems, etc. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
  - 来源: https://attack.mitre.org/mitigations/M1035/
  - 引用: "Prevent unnecessary remote access to file shares, hypervisors, sensitive systems, etc."
- NIST SP 800-207 (Zero Trust): 所有访问必须通过策略决策点
- Sygnia ESXi Ransomware Report: ESXi 勒索攻击中攻击者利用内部网络路径横向移动至虚拟化基础设施，强调了访问控制点对纵深防御的重要性
  - 来源: https://www.sygnia.co/blog/esxi-ransomware-attacks/

**设计依据**: 企业内网核心安全实践——所有对内网区域的访问必须通过堡垒机（Jump Server）。堡垒机是唯一的多区域入口点，三个 zone 互相完全隔离，只能通过堡垒机访问。这对应真实企业中的"跳板机架构"或"RDP 网关架构"，也是零信任架构中"策略执行点 (PEP)"的具体实现。

---

## 模板与 ATT&CK 战术映射总表

| 模板 | 主要 ATT&CK 战术 | 对应技术 | 缓解措施 |
|------|-----------------|---------|---------|
| dmz_simple | Initial Access (TA0001) | T1190 Exploit Public-Facing Application | M1030 Network Segmentation |
| dmz_dual | Initial Access + Lateral Movement | T1190 + T1210 | M1030 |
| 3tier | Lateral Movement (TA0008) | T1210, T1021 | M1030 |
| 4tier/5tier | Lateral Movement + Discovery | T1210, T1021, T1046 | M1030 |
| tree | Lateral Movement + Discovery | T1210, T1046 | M1030 |
| dual-dmz | Lateral Movement + Defense Evasion | T1210, T1021 | M1030 + 单向 ACL |
| asymmetric-acl | Lateral Movement + Command & Control | T1021 (反向连接失败) | M1030 + 非对称 ACL |
| multi-path | Lateral Movement + Discovery | T1210, T1046 | M1030 + Honeypot |
| bastion | Lateral Movement + Credential Access | T1021, T1555 | M1030 + M1035 |

---

## 参考文献列表

1. MITRE ATT&CK — Lateral Movement (TA0008)
   - https://attack.mitre.org/tactics/TA0008/

2. MITRE ATT&CK — Exploitation of Remote Services (T1210)
   - https://attack.mitre.org/techniques/T1210/

3. MITRE ATT&CK — Remote Services (T1021)
   - https://attack.mitre.org/techniques/T1021/

4. MITRE ATT&CK — Network Service Discovery (T1046)
   - https://attack.mitre.org/techniques/T1046/

5. MITRE ATT&CK — Credentials from Password Stores (T1555)
   - https://attack.mitre.org/techniques/T1555/

6. MITRE ATT&CK — Network Segmentation (M1030)
   - https://attack.mitre.org/mitigations/M1030/

7. MITRE ATT&CK — Limit Access to Resource Over Network (M1035)
   - https://attack.mitre.org/mitigations/M1035/

8. NIST SP 800-94 — Guide to Intrusion Detection and Prevention Systems (IDPS)
   - https://csrc.nist.gov/pubs/sp/800/94/final

9. NIST SP 800-207 — Zero Trust Architecture
   - https://csrc.nist.gov/pubs/sp/800/207/final

10. NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management
    - https://csrc.nist.gov/pubs/sp/800/61/r3/final

11. The DFIR Report — Ryuk's Return (真实事件响应报告，展示攻击者使用 AdFind/nltest 进行网络发现)
    - https://thedfirreport.com/2020/10/08/ryuks-return/

12. The DFIR Report — Ryuk in 5 Hours (真实事件响应报告，5 小时内从钓鱼到全域勒索)
    - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/

13. Sygnia — ESXi Ransomware Attacks: Evolution, Impact, and Defense Strategy
    - https://www.sygnia.co/blog/esxi-ransomware-attacks/

14. Anthropic — Disrupting the first reported AI-orchestrated cyber espionage campaign
    - https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf
    - 引用: "the adversary used Claude Code to enumerate internal network services and endpoints across targeted environments"
