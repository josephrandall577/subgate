#!/usr/bin/env bash
# SubGate 更新脚本：拉新代码 → 重新构建 → 重启 → 健康检查。data/ 内的机密与运行配置不受影响。
set -euo pipefail
cd "$(dirname "$0")"
DATA=data

[ -d .git ] && git pull --ff-only
go build -o subgate .

if systemctl is-active subgate >/dev/null 2>&1; then
  systemctl restart subgate
else
  pkill -f "$(pwd)/subgate -data" 2>/dev/null || pkill -f './subgate -data' 2>/dev/null || true
  sleep 0.5
  nohup ./subgate -data "$DATA" >>subgate.log 2>&1 &
fi

sleep 1
PANEL=$(grep -o '"panel_path": *"[^"]*"' "$DATA/secrets.json" | sed 's/.*"\([^"]*\)"$/\1/')
ADMINADDR=$(grep -o '"admin_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*"\([^"]*\)"$/\1/')
[[ "$ADMINADDR" == :* ]] && ADMINADDR="127.0.0.1$ADMINADDR"
GWPORT=$(grep -o '"gateway_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*:\([0-9]*\)".*/\1/')

OK=1
curl -sf -o /dev/null "http://$ADMINADDR/$PANEL/" && echo "健康检查: 管理后台 OK" || {
  echo "失败: 管理后台无响应"
  OK=0
}
(exec 3<>"/dev/tcp/127.0.0.1/$GWPORT") 2>/dev/null && echo "健康检查: 网关端口 OK" || {
  echo "失败: 网关端口不通"
  OK=0
}
[ "$OK" = 1 ] && echo "更新完成" || exit 1
