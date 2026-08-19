#!/usr/bin/env bash
# SubGate 更新：从 GitHub 拉新代码 → 重新构建 → 重启 → 健康检查
# data/ 内的机密（密码、后台路径）与运行配置（名单、上游）不受影响。
set -euo pipefail
cd "$(dirname "$0")"
DATA=data
REF=${SUBGATE_REF:-main}

if [ -d .git ]; then
  echo "== 拉取最新代码 (origin/$REF)"
  git fetch --depth 1 origin "$REF"
  git reset --hard FETCH_HEAD
  echo "   代码版本: $(git rev-parse --short HEAD)"
else
  echo "警告: 非 git 目录，跳过拉取，仅重新构建"
fi

go build -o subgate .

if systemctl is-active subgate >/dev/null 2>&1; then
  systemctl restart subgate
else
  pkill -f "$(pwd)/subgate -data" 2>/dev/null || true
  sleep 0.5
  nohup "$(pwd)/subgate" -data "$DATA" >>subgate.log 2>&1 &   # 绝对路径启动，上面 pkill 才能匹配到
fi

sleep 1.5
PANEL=$(grep -o '"panel_path": *"[^"]*"' "$DATA/secrets.json" | sed 's/.*"\([^"]*\)"$/\1/')
ADMINADDR=$(grep -o '"admin_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*"\([^"]*\)"$/\1/')
[[ "$ADMINADDR" == :* ]] && ADMINADDR="127.0.0.1$ADMINADDR"
GWPORT=$(grep -o '"gateway_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*:\([0-9]*\)".*/\1/')

OK=1
if curl -sf -o /dev/null "http://$ADMINADDR/$PANEL/"; then echo "健康检查: 管理后台 OK"; else echo "失败: 管理后台无响应"; OK=0; fi
if (exec 3<>"/dev/tcp/127.0.0.1/$GWPORT") 2>/dev/null; then echo "健康检查: 网关端口 OK"; else echo "失败: 网关端口不通"; OK=0; fi
if [ "$OK" = 1 ]; then echo "更新完成（配置与机密已保留）"; else exit 1; fi
