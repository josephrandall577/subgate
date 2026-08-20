#!/usr/bin/env bash
# SubGate 一键部署：从 GitHub 获取源码 → 交互配置 → 构建 → 生成机密 → 启动 → 打印+落盘访问信息
#
#   curl -fsSL https://raw.githubusercontent.com/josephrandall577/subgate/main/deploy.sh | bash
#   或在已 clone 的目录内直接 ./deploy.sh（会先 git pull 更新）
#
# 可用环境变量覆盖：
#   SUBGATE_REPO  源码仓库地址（默认本项目）
#   SUBGATE_DIR   源码存放目录（默认 ~/subgate）
#   SUBGATE_REF   分支或标签（默认 main）
set -euo pipefail

REPO=${SUBGATE_REPO:-https://github.com/josephrandall577/subgate.git}
REF=${SUBGATE_REF:-main}
DIR=${SUBGATE_DIR:-$HOME/subgate}
DATA=data

command -v git >/dev/null || {
  echo "需要 git"
  exit 1
}
# Go ≥1.21 才能按 go.mod 自动下载所需工具链;缺失或太老则装官方最新版
go_ok() {
  command -v go >/dev/null || return 1
  local v
  v=$(go env GOVERSION)
  v=${v#go}
  [ "$(printf '%s\n' 1.21 "$v" | sort -V | head -1)" = "1.21" ]
}
if ! go_ok; then
  echo "== 未找到可用 Go(需 ≥1.21),安装官方工具链…"
  GOVER=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)
  case $(uname -m) in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; *)
    echo "未知架构,请手动安装 Go: https://go.dev/dl/"
    exit 1
    ;;
  esac
  SUDO=""
  [ "$(id -u)" != 0 ] && SUDO=sudo
  $SUDO rm -rf /usr/local/go
  curl -fsSL "https://go.dev/dl/${GOVER}.linux-${ARCH}.tar.gz" | $SUDO tar -C /usr/local -xz
  export PATH=$PATH:/usr/local/go/bin
  go version
fi

# ── 获取源码 ──
# 以本地文件方式执行且自身就在仓库里 → 原地更新；
# curl|bash（无脚本文件）→ 始终 clone/更新到 $DIR，不受当前目录影响。
# 获取代码会连本脚本一起替换，而 bash 是增量读取脚本的，因此拉完代码后
# 用新版本重新 exec 一次，后续向导与构建全跑在新代码上。
if [ -z "${SUBGATE_REEXEC:-}" ]; then
  SELF=${BASH_SOURCE[0]:-}
  SELFDIR=""
  [ -n "$SELF" ] && [ -f "$SELF" ] && SELFDIR=$(cd "$(dirname "$SELF")" && pwd)

  if [ -n "$SELFDIR" ] && [ -d "$SELFDIR/.git" ] && grep -q '^module subgate' "$SELFDIR/go.mod" 2>/dev/null; then
    echo "== 本地源码目录 ${SELFDIR}，更新代码…"
    cd "$SELFDIR"
    git pull --ff-only || echo "(git pull 跳过，使用当前工作区代码)"
  elif [ -d "$DIR/.git" ]; then
    echo "== 更新已有源码 $DIR"
    git -C "$DIR" fetch --depth 1 origin "$REF"
    git -C "$DIR" reset --hard FETCH_HEAD # data/ 已 gitignore，不受影响
    cd "$DIR"
  else
    echo "== 从 $REPO 获取源码到 $DIR"
    git clone --depth 1 --branch "$REF" "$REPO" "$DIR"
    cd "$DIR"
  fi
  echo "   代码版本: $(git rev-parse --short HEAD)"
  SUBGATE_REEXEC=1 exec bash "$(pwd)/deploy.sh"
fi

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# curl|bash 时 stdin 是脚本本身，交互输入必须读 /dev/tty；存在但不可用时也要降级
if { : </dev/tty; } 2>/dev/null; then TTY=/dev/tty; else
  TTY=""
  echo "== 非交互环境：所有选项使用默认值（部署后可在后台设置页修正）"
fi
ask() {
  local v=""
  [ -n "$TTY" ] && { read -rp "$1 [$2]: " v <"$TTY" || true; }
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
  PASS="(沿用原密码，见 $DATA/deploy-info.txt)"
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
  # 匹配不带路径前缀，以兼容旧版本用 ./subgate 启动的残留进程（单主机单实例部署）
  pkill -f '[/.]subgate -data' 2>/dev/null || true
  sleep 0.5
  nohup "$(pwd)/subgate" -data "$DATA" >>subgate.log 2>&1 &
fi

sleep 1.5
if curl -sf -o /dev/null "http://127.0.0.1:$ADMINPORT/$PANEL/"; then
  echo "健康检查: 管理后台 OK"
else
  echo "警告: 管理后台无响应，请检查日志 (journalctl -u subgate 或 $(pwd)/subgate.log)"
fi

INFO=$(
  cat <<EOF
========================================
SubGate 部署完成 $(date '+%F %T')
源码目录:  $(pwd)  (版本 $(git rev-parse --short HEAD))
网关入口:  http://<本机>:$GWPORT   (Cloudflare Tunnel 指向 http://localhost:$GWPORT)
订阅路径:  $SUBPATH
管理后台:  http://127.0.0.1:$ADMINPORT/$PANEL/
管理账号:  admin
管理密码:  $PASS
提示: Cloudflare Zero Trust 中真实IP头保持 CF-Connecting-IP 即可
更新: cd $(pwd) && ./update.sh
========================================
EOF
)
echo "$INFO"
if [ "$NEW_SECRET" = 1 ]; then
  echo "$INFO" >"$DATA/deploy-info.txt"
  chmod 600 "$DATA/deploy-info.txt"
  echo "(访问信息已保存到 $(pwd)/$DATA/deploy-info.txt)"
fi
exit 0
