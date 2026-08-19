#!/usr/bin/env bash
# SubGate 一键部署向导：交互收集配置 → 构建 → 生成机密 → 启动 → 打印+落盘访问信息
set -euo pipefail
cd "$(dirname "$0")"
DATA=data

command -v go >/dev/null || {
  echo "需要 Go 工具链 (https://go.dev/dl/)"
  exit 1
}

ask() {
  local v
  read -rp "$1 [$2]: " v
  echo "${v:-$2}"
}

echo "== SubGate 部署向导 =="
UPSTREAM=$(ask "机场后端地址(含协议)" "https://backend.example.com")
SUBPATH=$(ask "订阅路径前缀" "/api/v1/client/subscribe")
GWPORT=$(ask "网关监听端口(Cloudflare Tunnel 指向它)" "18080")
ADMINPORT=$(ask "管理后台端口(仅绑定127.0.0.1，经隧道/SSH访问)" "18081")
HDR=$(ask "真实IP头(Cloudflare 用 CF-Connecting-IP)" "CF-Connecting-IP")
TRUSTED=$(ask "受信代理网段(逗号分隔，本机 cloudflared 保持默认)" "127.0.0.0/8,::1/128")
CERTDOMAIN=$(ask "证书监控域名(对外订阅域名，可空)" "")

echo "构建..."
go build -o subgate .

NEW_SECRET=0
if [ ! -f "$DATA/secrets.json" ]; then
  PASS=$(openssl rand -hex 12)
  PANEL=$(openssl rand -hex 8)
  ./subgate -init -data "$DATA" -user admin -pass "$PASS" -panel "$PANEL"
  NEW_SECRET=1
else
  echo "已存在 secrets.json：保留原密码与后台路径"
  PASS="(沿用原密码，见首次部署记录)"
  PANEL=$(grep -o '"panel_path": *"[^"]*"' "$DATA/secrets.json" | sed 's/.*"\([^"]*\)"$/\1/')
fi

if [ ! -f "$DATA/config.json" ]; then
  TP_JSON=""
  IFS=',' read -ra ARR <<<"$TRUSTED"
  for x in "${ARR[@]}"; do TP_JSON+="\"$(echo "$x" | xargs)\","; done
  mkdir -p "$DATA"
  cat >"$DATA/config.json" <<EOF
{
  "upstream": "$UPSTREAM",
  "sub_path": "$SUBPATH",
  "gateway_addr": ":$GWPORT",
  "admin_addr": "127.0.0.1:$ADMINPORT",
  "panel_title": "SubGate",
  "real_ip_header": "$HDR",
  "trusted_proxies": [${TP_JSON%,}],
  "rate_per_min": 20,
  "rate_burst": 5,
  "susp_token_ips": 3,
  "susp_ip_tokens": 3,
  "cert_domain": "$CERTDOMAIN",
  "asn_url_template": "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%d/%s"
}
EOF
else
  echo "已存在 config.json：保留运行配置（改上游请在后台设置页操作）"
  ADMINPORT=$(grep -o '"admin_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*:\([0-9]*\)".*/\1/')
  GWPORT=$(grep -o '"gateway_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*:\([0-9]*\)".*/\1/')
fi

# 启动：优先 systemd（root），否则 nohup
if command -v systemctl >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
  cat >/etc/systemd/system/subgate.service <<EOF
[Unit]
Description=SubGate subscription gateway
After=network.target

[Service]
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/subgate -data $(pwd)/$DATA
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now subgate
  systemctl restart subgate
else
  pkill -f "$(pwd)/subgate -data" 2>/dev/null || pkill -f './subgate -data' 2>/dev/null || true
  sleep 0.5
  nohup ./subgate -data "$DATA" >>subgate.log 2>&1 &
fi

sleep 1
if curl -sf -o /dev/null "http://127.0.0.1:$ADMINPORT/$PANEL/"; then
  echo "健康检查: 管理后台 OK"
else
  echo "警告: 管理后台无响应，请检查日志 (journalctl -u subgate 或 subgate.log)"
fi

INFO=$(
  cat <<EOF
========================================
SubGate 部署完成 $(date '+%F %T')
网关入口:  http://<本机>:$GWPORT   (Cloudflare Tunnel 指向 http://localhost:$GWPORT)
订阅路径:  $SUBPATH
管理后台:  http://127.0.0.1:$ADMINPORT/$PANEL/
管理账号:  admin
管理密码:  $PASS
提示: Cloudflare Zero Trust 中真实IP头保持 CF-Connecting-IP 即可
========================================
EOF
)
echo "$INFO"
[ "$NEW_SECRET" = 1 ] && echo "$INFO" >"$DATA/deploy-info.txt" && chmod 600 "$DATA/deploy-info.txt" && echo "(访问信息已保存到 $DATA/deploy-info.txt)"
exit 0
