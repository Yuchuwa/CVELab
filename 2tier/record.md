原脚本第649行写死了模板文件夹是enterprise3。故新建verify_enterprise2_guided_batch.py进行验证，修改第649行模板文件夹名为enterprise2，未作其他修改

--cases 的硬编码值（b00-b06）全是 3 CVE，与 enterprise_2tier 的两个 injection point 不兼容。需要改用 --case-manifest。
创建一个 manifest JSON 文件




问题出在 YAML 锚点（anchor）的引用链断裂。
low 档（第 44-61 行）只定义了 3 个锚点：
- &id001（第 49 行，port 80）
- &id002（第 54 行，port 6379）
- &id005（第 59 行，port 8080）
但 medium 档（第 62-145 行）引用了 不存在 的锚点：
- 第 74 行：ports: *id003 ← &id003 未定义
- 第 79 行：ports: *id004 ← &id004 未定义
- 第 117 行也引用 *id008 ← &id008 只在 medium 自身定义（第 100 行），所以这个合法
同时第 139、143 行也引用了 *id003、*id004，同样未定义。


解决方法：把所有decoy noise里的app字段换成了dmz

verify_enterprise2_guided_batch.py 第 54-90 行写死了 7 个 case：
CASES = (
    {"id": "b00-baseline", "cves": ["CVE-2012-1823", "CVE-2018-16509", "CVE-2019-9193"], ...},
    {"id": "b01-dmz-middleware", "cves": ["CVE-2014-3120", "CVE-2018-16509", "CVE-2019-9193"], ...},
    ...
)
每个 case 固定 3 个 CVE，对 enterprise_2tier（只有 2 个 injection point）不可用。所以 --cases b00-baseline 这类写法对两层无效，只能用 --case-manifest 传入自定义的 2 CVE case。


目前只有一个可搭建并运行成功的二层环境，Agent能稳定打通第二层，但在读取/flag时返回内容不正确


templates/enterprise_2tier/clab.yaml
templates/enterprise_2tier/ansible/base.yaml
templates/enterprise_2tier/template.yaml
.env
data/range_matrices/enterprise_2tier_manifest.json
data/range_matrices/enterprise_2tier_smoke.json
data/range_matrices/enterprise_2tier_expanded.json
data/range_matrices/enterprise_2tier_agent.json
data/range_matrices/enterprise_2tier_rerun.json
data/guide_ablation/2tier_smoke/
data/guide_ablation/2tier_expanded/
data/guide_ablation/2tier_agent/
data/guide_ablation/2tier_rerun/
docs/WORK_PROGRESS_REPORT.md


原本用于dmz-web的镜像比较简单，没有python3/psql 不具备sql访问能力
通过预安装库以及采用原本app层的atom进行解决