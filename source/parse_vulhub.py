#!/usr/bin/env python3
"""
Parse vulhub environments and generate CSV with vulnerability information.
"""

import os
import re
import csv
from pathlib import Path

try:
    import tomli
except ImportError:
    import tomllib as tomli


def parse_cve_year(cve_str):
    """Extract year from CVE string."""
    if not cve_str:
        return None
    match = re.search(r'CVE-(\d{4})', cve_str)
    if match:
        return int(match.group(1))
    return None


def extract_references_from_readme(readme_path):
    """Extract reference links from README.md file."""
    references = []

    if not os.path.exists(readme_path):
        return ""

    with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Find the References section (support: "Reference:", "References:", "Reference Links:")
    ref_section_match = re.search(
        r'(?:Reference\s*(?:Links?)?|References?)\s*:\s*\n((?:[ \t]*[-*]\s*[^\n]+\n)+)',
        content,
        re.IGNORECASE | re.MULTILINE
    )

    if ref_section_match:
        ref_block = ref_section_match.group(1)
        # Extract URLs from the reference block
        url_pattern = r'<(https?://[^>]+)>|(https?://[^\s\)]+)'
        urls = re.findall(url_pattern, ref_block)
        for url_tuple in urls:
            url = url_tuple[0] if url_tuple[0] else url_tuple[1]
            if url:
                references.append(url)

    return '; '.join(references)


def extract_title_from_readme(readme_path):
    """Extract title (first heading) from README.md file."""
    if not os.path.exists(readme_path):
        return ""

    with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
        first_line = f.readline()

    # Extract title from markdown heading
    match = re.match(r'#\s+(.+)', first_line)
    if match:
        return match.group(1).strip()
    return ""


def get_runtime_capability(app_name):
    """
    根据 Vulhub 目录名推断运行时环境。
    返回元组: (Capability_Level, Runtime_Language)
    """
    app = app_name.lower().strip()

    # === 1. High Capability: 拥有完整解释器/编译环境 ===

    # [Java] - 适合上传 JSP/WAR, 内存马, 编译 class
    if any(k in app for k in [
        "activemq", "weblogic", "tomcat", "struts2", "spring", "shiro",
        "jenkins", "jboss", "fastjson", "elasticsearch", "log4j", "solr",
        "maven", "jetty", "glassfish", "hadoop", "flink", "kafka", "spark",
        "confluence", "jira", "liferay", "neo4j", "nexus", "ofbiz", "openfire",
        "rocketmq", "skywalking", "unomi", "xxl-job", "zabbix", "apereo-cas",
        "apache-druid", "apache-cxf", "dubbo", "hertzbeat", "hugegraph",
        "jackson", "jimureport", "kkfileview", "metabase", "metersphere",
        "mojarra", "nacos", "opentsdb", "teamcity", "xstream", "java"
    ]):
        return "High", "Java"

    # [PHP] - 适合上传 PHP Webshell
    if any(k in app for k in [
        "php", "wordpress", "thinkphp", "drupal", "joomla", "laravel",
        "discuz", "ecshop", "typecho", "adminer", "phpmyadmin", "cacti",
        "cmsms", "craftcms", "elfinder", "gitlist", "livewire", "magento",
        "phpmailer", "phpunit", "showdoc", "tikiwiki", "v2board"
    ]):
        return "High", "PHP"

    # [Python] - 适合反弹 Shell, 运行 Proxy 脚本
    if any(k in app for k in [
        "python", "django", "flask", "airflow", "celery", "jupyter",
        "supervisor", "saltstack", "gradio", "jumpserver", "langflow",
        "pgadmin", "scrapy", "superset", "uwsgi"
    ]):
        return "High", "Python"

    # [NodeJS] - 适合反弹 Shell
    if any(k in app for k in [
        "node", "kibana", "electron", "nuxt", "next.js", "ghost",
        "mongo-express", "react", "rocketchat", "vite", "yapi"
    ]):
        return "High", "NodeJS"

    # [Go/Ruby/Perl/Shell] - 通常有 Shell 环境
    if any(k in app for k in ["gitea", "gogs", "grafana", "minio", "1panel", "apisix"]):
        return "High", "Go/Binary"
    if any(k in app for k in ["ruby", "rails", "gitlab"]):
        return "High", "Ruby"
    if any(k in app for k in ["webmin", "perl"]):
        return "High", "Perl"
    if any(k in app for k in ["bash", "cgi", "git"]):
        return "High", "Shell"

    # === 2. Low Capability: 受限环境 (死胡同) ===

    # [Database] - 只有数据库进程，无 Shell 工具
    if any(k in app for k in [
        "redis", "mysql", "postgres", "mongo", "couchdb", "memcached",
        "influxdb", "h2database", "mssql", "mariadb", "rocksdb"
    ]):
        return "Low", "Database"

    # [Web Server] - 纯静态转发
    if any(k in app for k in ["nginx", "httpd", "lighttpd", "mini_httpd", "ingress-nginx"]):
        # 排除包含 apache- 前缀的 Java 组件
        if "apache-" not in app:
            return "Low", "WebServer"

    # [Library/Tools] - 库漏洞，环境极简
    if any(k in app for k in [
        "ffmpeg", "imagemagick", "ghostscript", "openssl", "openssh",
        "libssh", "librsvg", "polkit", "rsync", "samba", "cups"
    ]):
        return "Low", "Library/Tool"

    # [Infrastructure]
    if any(k in app for k in ["dns", "bind", "opensmtpd"]):
        return "Low", "Infrastructure"

    # === 3. 兜底策略 ===
    # Vulhub 中未识别的通常是 Web 应用，倾向于 High，但标记 Unknown
    return "High", "Unknown-Web"


def determine_role(app_name, tags):
    """
    Determine the role of a vulnerability based on runtime capability and tags.

    Rules:
    - Jump_host: High runtime capability AND vulnerability can provide shell access
    - Data: Low runtime capability OR cannot get shell

    Returns tuple: (role, runtime_lang)
    """
    # Get runtime capability
    capability, runtime_lang = get_runtime_capability(app_name)

    # If capability is Low, it's a dead end
    if capability == "Low":
        return "Data", runtime_lang

    # Tags that indicate the vulnerability can provide shell access
    shell_access_tags = {
        "RCE",  # Remote Code Execution
        "Deserialization",  # Can lead to RCE
        "File Upload",  # Can lead to webshell
        "SSTI",  # Server-Side Template Injection - can lead to RCE
        "Expression Injection",  # Can lead to RCE
        "Environment Injection",  # Can lead to RCE
        "Backdoor",  # Already has backdoor
    }

    # Check if any tag indicates shell access capability
    for tag in tags:
        if tag in shell_access_tags:
            return "Jump_host", runtime_lang

    # Has runtime environment but cannot get shell directly
    return "Data", runtime_lang


def parse_environments(vulhub_path, output_csv):
    """Parse environments.toml and generate CSV."""
    env_file = os.path.join(vulhub_path, 'environments.toml')

    if not os.path.exists(env_file):
        print(f"Error: {env_file} not found")
        return

    # Parse TOML file
    with open(env_file, 'rb') as f:
        data = tomli.load(f)

    results = []

    for env in data.get('environment', []):
        name = env.get('name', '')
        cve_list = env.get('cve', [])
        path_rel = env.get('path', '')
        tags = env.get('tags', [])
        app = env.get('app', '')

        # Skip entries without CVE
        if not cve_list:
            continue

        # Join CVEs with comma
        valid_cves = ', '.join(cve_list)

        # Build full path to README
        readme_path = os.path.join(vulhub_path, path_rel, 'README.md')
        if not os.path.exists(readme_path):
            readme_path = os.path.join(vulhub_path, path_rel, 'readme.md')

        # Extract references from README
        references = extract_references_from_readme(readme_path)
        if not references:
            references = 'N/A'

        # Get folder name (first level directory under vulhub)
        folder_name = path_rel.split(os.sep)[0] if os.sep in path_rel else path_rel

        # Get type from tags (join all tags with comma)
        vuln_type = ', '.join(tags) if tags else 'Other'

        # Determine role based on app runtime environment and vulnerability tags
        role, runtime_lang = determine_role(app, tags)

        # Build result row
        # valid_cves is already a string (either joined CVEs or "unknown")
        result = {
            'Name': folder_name,
            'CVE': valid_cves,
            'Description': name,
            'Reference': references,
            'Path': os.path.dirname(os.path.abspath(readme_path)) if os.path.exists(readme_path) else '',
            'Type': vuln_type,
            'Role': role,
            'Runtime_lang': runtime_lang,
            'Startup': 'docker compose up'
        }

        results.append(result)

    # Write to CSV
    fieldnames = ['Name', 'CVE', 'Description', 'Reference', 'Path', 'Type', 'Role', 'Runtime_lang', 'Startup']

    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Generated CSV with {len(results)} entries: {output_csv}")


def main():
    # Default paths
    script_dir = Path(__file__).parent
    # Script is in source/ folder, so vulhub is in ./vulhub
    vulhub_path = script_dir / 'vulhub'
    output_csv = script_dir / 'vulhub_cves_20260114.csv'

    # Allow command line overrides
    import sys
    if len(sys.argv) > 1:
        vulhub_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_csv = sys.argv[2]

    parse_environments(str(vulhub_path), str(output_csv))


if __name__ == '__main__':
    main()
