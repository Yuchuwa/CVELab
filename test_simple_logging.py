#!/usr/bin/env python3
"""测试日志系统"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from main import run


user_request = """
创建一个简单的渗透测试实验室：
- 1 个 Kali Linux 作为攻击机
- 1 个 Redis 服务器作为靶机
- 1 个 Alpine 路由器连接它们
- 复杂度：simple
"""

print("开始测试...")
result = run(user_request)

# 检查日志文件
from session_utils import get_current_session_id, get_session_output_dir

session_id = get_current_session_id()
if session_id:
    log_file = os.path.join(get_session_output_dir(session_id), f"{session_id}.log")
    print(f"\n{'='*80}")
    print(f"日志文件检查")
    print(f"{'='*80}")
    print(f"路径: {log_file}")

    if os.path.exists(log_file):
        size = os.path.getsize(log_file)
        print(f"文件大小: {size} 字节")
        if size > 0:
            print(f"✅ 日志文件有内容")
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            print(f"总行数: {len(lines)}")
            print(f"\n前 20 行内容:")
            print("-"*80)
            for line in lines[:20]:
                print(line.rstrip())
            print("-"*80)
        else:
            print(f"❌ 日志文件为空")
    else:
        print(f"❌ 日志文件不存在")

print(f"\n{'='*80}")
print(f"测试结果: {'成功' if result.get('is_complete') else '失败'}")
print(f"{'='*80}")
