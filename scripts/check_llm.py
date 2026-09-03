#!/usr/bin/env python3
"""验证 LLM 代理 URL / 协议 / 模型名是否可用。

用法:
    python3 scripts/check_llm.py --url http://localhost:3000 --model deepseek-v4-pro --api-key sk-xxx

同时探测:
  1. /v1/models           — 网关是否可达、模型名是否注册
  2. /v1/messages         — Anthropic 协议 (Claude Agent SDK 用这个)
  3. /v1/chat/completions — OpenAI 协议
"""

import argparse
import json
import sys

try:
    import requests
except ImportError:
    print("缺少 requests，请先: pip install requests")
    sys.exit(1)


def probe(url, method="GET", headers=None, payload=None):
    try:
        if method == "POST":
            r = requests.post(url, headers=headers, json=payload, timeout=15)
        else:
            r = requests.get(url, headers=headers, timeout=15)
        return r.status_code, r.text[:500]
    except requests.exceptions.ConnectionError as e:
        return None, f"CONNECTION ERROR: {e}"
    except requests.exceptions.Timeout:
        return None, "TIMEOUT"
    except Exception as e:
        return None, f"ERROR: {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:3000", help="base url (origin, 不带路径)")
    ap.add_argument("--model", default="deepseek-v4-pro")
    ap.add_argument("--api-key", default="sk-test")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    auth = {"Authorization": f"Bearer {args.api_key}"}
    json_hdr = {**auth, "Content-Type": "application/json"}

    print(f"目标: {base}\n模型: {args.model}\n")

    # 1. 可达性 + 模型注册
    print("[1] GET /v1/models")
    code, body = probe(f"{base}/v1/models", headers=auth)
    print(f"    status={code}")
    if code == 200:
        try:
            ids = [m.get("id") for m in json.loads(body).get("data", [])]
            print(f"    模型列表: {ids}")
            print(f"    '{args.model}' 在列表中: {args.model in ids}")
        except Exception:
            print(f"    (无法解析模型列表) body={body}")
    else:
        print(f"    body={body}")

    # 2. Anthropic 协议
    print("\n[2] POST /v1/messages (Anthropic, Claude Agent SDK 使用)")
    code, body = probe(
        f"{base}/v1/messages", method="POST", headers=json_hdr,
        payload={
            "model": args.model,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "ping"}],
        },
    )
    print(f"    status={code}")
    print(f"    body={body}")

    # 3. OpenAI 协议
    print("\n[3] POST /v1/chat/completions (OpenAI)")
    code, body = probe(
        f"{base}/v1/chat/completions", method="POST", headers=json_hdr,
        payload={
            "model": args.model,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "ping"}],
        },
    )
    print(f"    status={code}")
    print(f"    body={body}")

    print("\n结论:")
    print("  - 若 [1] 无法连接 → URL/端口/DNS 问题 (容器内用宿主 IP 或 172.17.0.1)")
    print("  - 若 [1] 200 但模型名不在列表 → 换 [1] 列表里存在的模型名")
    print("  - 若 [2] 200 → 可直接给 Claude Agent SDK 用 (LLM_BASE_URL 填 origin, 不带路径)")
    print("  - 若只有 [3] 200 → 这是 OpenAI 协议网关, Claude Agent SDK 不兼容")


if __name__ == "__main__":
    main()
