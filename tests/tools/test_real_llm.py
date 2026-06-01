#!/usr/bin/env python3
"""
独立的真实LLM测试

直接测试Claude API调用，不依赖其他模块
"""

import os
import sys
import requests
import json
from pathlib import Path


def load_env():
    """加载.env文件"""
    # 项目根目录的.env
    env_path = Path(__file__).parent.parent.parent / ".env"

    # 如果不存在，尝试当前目录
    if not env_path.exists():
        env_path = Path.cwd() / ".env"

    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip().strip('"')
        print("✅ .env文件加载成功")
        print(f"   从: {env_path}")
    else:
        print("❌ .env文件不存在")
        # 不退出，尝试使用环境变量
        if not os.getenv("API_KEY"):
            print("⚠️  API_KEY环境变量也未设置")
            sys.exit(1)


def test_claude_api_call():
    """测试真实的Claude API调用"""
    print("=" * 60)
    print("🧪 测试真实Claude API调用")
    print("=" * 60)

    # 加载环境变量
    load_env()

    api_key = os.getenv("API_KEY")
    base_url = os.getenv("BASE_URL")
    model = os.getenv("MODEL")

    if not api_key:
        print("❌ API_KEY未设置")
        return False

    print(f"📋 API配置:")
    print(f"   Base URL: {base_url}")
    print(f"   Model: {model}")
    print(f"   API Key: {api_key[:20]}...")

    # 构建测试prompt
    test_prompt = """你是一个网络安全研究员。请分析以下CVE：

CVE-2023-46604 - Apache ActiveMQ远程代码执行漏洞

这是一个严重的反序列化漏洞，影响Apache ActiveMQ消息代理。

请分析：
1. 漏洞类型
2. 攻击向量
3. MITRE ATT&CK阶段
4. 推荐的测试方法

请以JSON格式返回分析结果。"""

    print(f"\n📨 发送API请求...")
    print(f"   Prompt长度: {len(test_prompt)} 字符")

    # 尝试不同的API端点
    possible_endpoints = [
        f"{base_url.rstrip('/')}/v1/messages",  # 标准端点
        "https://api.anthropic.com/v1/messages"  # 备用官方端点
    ]

    successful_response = None

    for endpoint in possible_endpoints:
        print(f"\n   尝试端点: {endpoint}")

        url = endpoint
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        payload = {
            "model": model,
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": test_prompt}]
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            print(f"   HTTP状态码: {response.status_code}")

            if response.status_code == 200:
                try:
                    result = response.json()
                    if "content" in result:
                        successful_response = result
                        print(f"   ✅ 成功!")
                        break  # 成功，退出循环
                    else:
                        print(f"   ⚠️  JSON格式不符")
                except ValueError as e:
                    print(f"   ❌ JSON解析失败: {e}")
            else:
                print(f"   ❌ 状态码错误")

        except requests.exceptions.RequestException as e:
            print(f"   ❌ 请求失败: {e}")

        if successful_response:
            break  # 成功，退出循环

    if not successful_response:
        print(f"\n❌ 所有端点都失败")
        return False

    claude_response = successful_response["content"][0]["text"]

    print(f"✅ API调用成功!")
    print(f"   响应长度: {len(claude_response)} 字符")
    print(f"   模型: {successful_response.get('model', model)}")

    print(f"\n📄 Claude响应（前500字符）:")
    print(claude_response[:500])
    print("..." if len(claude_response) > 500 else "")

    # 验证响应包含相关内容
    keywords = ["ActiveMQ", "反序列化", "RCE", "MITRE", "漏洞"]
    found_keywords = [kw for kw in keywords if kw.lower() in claude_response.lower()]

    print(f"\n🔍 关键词检测:")
    for kw in keywords:
        found = kw.lower() in claude_response.lower()
        print(f"   {'✅' if found else '❌'} {kw}: {'找到' if found else '未找到'}")

    return True


def test_different_cves():
    """测试不同CVE产生不同分析"""
    print(f"\n{'=' * 60}")
    print(f"🔄 测试不同CVE的分析")
    print(f"{'=' * 60}")

    load_env()

    api_key = os.getenv("API_KEY")
    base_url = os.getenv("BASE_URL")
    model = os.getenv("MODEL")

    cves = [
        {
            "id": "CVE-2023-46604",
            "prompt": f"分析CVE-2023-46604 ActiveMQ RCE漏洞的攻击向量"
        },
        {
            "id": "CVE-2021-44228",
            "prompt": f"分析CVE-2021-44228 Log4j RCE漏洞的利用方式"
        },
        {
            "id": "CVE-2014-0160",
            "prompt": f"分析CVE-2014-0160 Heartbleed漏洞的影响范围"
        }
    ]

    responses = {}

    for cve in cves:
        print(f"\n{'=' * 40}")
        print(f"测试 {cve['id']}")
        print(f"{'=' * 40}")

        url = f"{base_url.rstrip('/')}/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": model,
            "max_tokens": 500,
            "messages": [{"role": "user", "content": cve['prompt']}]
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            result = response.json()

            if "content" in result:
                response_text = result["content"][0]["text"]
                responses[cve['id']] = response_text
                print(f"✅ 响应长度: {len(response_text)}")
            else:
                print(f"❌ API返回错误: {result.get('error', 'Unknown')}")

        except Exception as e:
            print(f"❌ 失败: {e}")

    # 分析结果
    successful_cves = len(responses)
    print(f"\n📊 测试结果:")
    print(f"   成功: {successful_cves}/{len(cves)}")

    if successful_cves >= 2:
        # 检查响应是否不同
        response_texts = list(responses.values())
        are_different = response_texts[0] != response_texts[1]
        print(f"   响应不同: {'✅ 是' if are_different else '❌ 否'}")

        # 检查每个响应是否包含对应的CVE信息
        for cve_id, response in responses.items():
            unique_id = cve_id.replace('-', '').replace('CVE', '').lower()
            relevant = unique_id in response.lower()
            print(f"   {cve_id} 相关性: {'✅ 高' if relevant else '❌ 低'}")

    return successful_cves >= 2


if __name__ == "__main__":
    print("🚀 开始真实LLM测试")

    # 测试1: 基本API调用
    basic_test = test_claude_api_call()

    # 测试2: 不同CVE分析
    if basic_test:
        test_different_cves()

    print(f"\n{'=' * 60})
    print(f"🎉 LLM测试完成!")
    print(f"{'=' * 60}")
