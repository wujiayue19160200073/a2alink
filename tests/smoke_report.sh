#!/usr/bin/env bash
set -u
export PYTHONPATH=/d/WorkBuddy-workspace/做开源工具/a2alink/src
export A2ALINK_HOME=$(mktemp -d)
REG=http://127.0.0.1:8933
a2a() { local sid="$1"; shift; A2ALINK_SESSION="$sid" python -c "import sys;from a2alink.cli import main;sys.exit(main(sys.argv[1:]))" --registry $REG "$@"; }

a2a s-rep-a session name 甲组 >/dev/null 2>&1
a2a s-rep-b session name 乙组 >/dev/null 2>&1

echo "--- 造数据：正常 2 条、内网 IP 1 条、凭据 2 条（挂起）---"
a2a s-rep-a say @乙组 "构建通过了" >/dev/null 2>&1
a2a s-rep-a say @乙组 "日志在 10.2.3.4 上" >/dev/null 2>&1
a2a s-rep-a say @乙组 "口令是 AKIAIOSFODNN7EXAMPLE 别外传" >/dev/null 2>&1
a2a s-rep-a say @乙组 "mysql://root:Passw0rd@10.0.0.8/db" >/dev/null 2>&1

echo
echo "===== logs report ====="
a2a s-rep-a logs report --hours 0

echo
echo "===== logs report --json（节选）====="
a2a s-rep-a logs report --hours 0 --json | python -c "
import json,sys
d=json.load(sys.stdin)
print('records:', d['records'])
print('by_decision:', d['by_decision'])
print('rules:', d.get('rules'))
print('chain ok:', d['chain']['ok'])
"
