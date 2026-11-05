#!/usr/bin/env bash
set -u
export PYTHONPATH=/d/WorkBuddy-workspace/做开源工具/a2alink/src
export A2ALINK_HOME=$(mktemp -d)
REG=http://127.0.0.1:8931
a2a() { local sid="$1"; shift; A2ALINK_SESSION="$sid" python -c "import sys;from a2alink.cli import main;sys.exit(main(sys.argv[1:]))" --registry $REG "$@"; }

echo "===== 1. 两个对话起名 + 打标签 ====="
a2a sess-ops-0001 session name 运维 | head -1
a2a sess-ops-0001 session tag 值班 数据库
a2a sess-wri-0002 session name 写手 | head -1
a2a sess-wri-0002 session tag 值班 文档

echo
echo "===== 2. 按标签寻址 ====="
echo "--- 歧义标签（应报错并列候选）---"
a2a sess-ops-0001 say 值班 "在吗" 2>&1 | head -4
echo "--- 唯一标签（应成功）---"
a2a sess-ops-0001 say 数据库 "MySQL 主从延迟 30s，看一眼" | head -3

echo
echo "===== 3. 会话列表带标签 ====="
a2a sess-ops-0001 session list

echo
echo "===== 4. 含连接串的消息 → 挂起而不是报错 ====="
a2a sess-ops-0001 say @写手 "用 mysql://root:Secr3t@10.0.9.9:3306/prod 连上去查" 2>&1 | head -12

echo
echo "===== 5. 审批队列 ====="
a2a sess-ops-0001 approvals list
PID=$(a2a sess-ops-0001 approvals list | grep -o 'apv-[0-9a-f]\{24\}' | head -1)
echo "审批件: $PID"

echo
echo "===== 6. 看内容 ====="
a2a sess-ops-0001 approvals show "$PID" 2>&1 | head -14

echo
echo "===== 7. 无 --yes 批准应被拒 ====="
a2a sess-ops-0001 approvals approve "$PID" --reason "测试环境允许" 2>&1 < /dev/null | head -3

echo
echo "===== 8. 带 --yes 批准并重发 ====="
a2a sess-ops-0001 approvals approve "$PID" --reason "测试环境凭据，客户已授权" --yes 2>&1 | head -5

echo
echo "===== 9. 对方收到了吗 ====="
a2a sess-wri-0002 check 2>&1 | head -14

echo
echo "===== 10. 审计统计 ====="
a2a sess-ops-0001 approvals stats
a2a sess-ops-0001 down >/dev/null 2>&1
