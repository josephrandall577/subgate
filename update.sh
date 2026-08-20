#!/usr/bin/env bash
# SubGate 更新：从 GitHub 拉新代码 → 重新构建 → 重启 → 健康检查
# data/ 内的机密（密码、后台路径）与运行配置（名单、上游）不受影响。
set -euo pipefail
cd "$(dirname "$0")"
DATA=data
REF=${SUBGATE_REF:-main}

# 本脚本会把自己一起更新掉。bash 是增量读取脚本文件的，边跑边改会执行到错位
# 内容（旧逻辑或语法碎片），所以：先只拉代码，然后用新版本重新执行一次。
if [ -z "${SUBGATE_REEXEC:-}" ]; then
  if [ -d .git ]; then
    echo "== 拉取最新代码 (origin/$REF)"
    git fetch --depth 1 origin "$REF"
    git reset --hard FETCH_HEAD
    echo "   代码版本: $(git rev-parse --short HEAD)"
  else
    echo "警告: 非 git 目录，跳过拉取，仅重新构建"
  fi
  SUBGATE_REEXEC=1 exec bash "$(pwd)/update.sh" "$@"
fi

echo "== 构建镜像并重启容器"
docker build -t subgate .

systemctl disable --now subgate 2>/dev/null || true # 停用旧 systemd 部署
pkill -f '[/.]subgate -data' 2>/dev/null || true    # 停掉旧 nohup 部署
docker rm -f subgate >/dev/null 2>&1 || true
docker run -d --name subgate --network host --restart unless-stopped \
  -v "$(pwd)/$DATA":/data -v /etc/localtime:/etc/localtime:ro subgate

sleep 1.5
PANEL=$(grep -o '"panel_path": *"[^"]*"' "$DATA/secrets.json" | sed 's/.*"\([^"]*\)"$/\1/')
ADMINADDR=$(grep -o '"admin_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*"\([^"]*\)"$/\1/')
[[ "$ADMINADDR" == :* ]] && ADMINADDR="127.0.0.1$ADMINADDR"
GWPORT=$(grep -o '"gateway_addr": *"[^"]*"' "$DATA/config.json" | sed 's/.*:\([0-9]*\)".*/\1/')

OK=1
if curl -sf -o /dev/null "http://$ADMINADDR/$PANEL/"; then echo "健康检查: 管理后台 OK"; else
  echo "失败: 管理后台无响应"
  OK=0
fi
if (exec 3<>"/dev/tcp/127.0.0.1/$GWPORT") 2>/dev/null; then echo "健康检查: 网关端口 OK"; else
  echo "失败: 网关端口不通"
  OK=0
fi
if [ "$OK" = 1 ]; then echo "更新完成（配置与机密已保留）"; else
  echo "排查: docker logs --tail 100 subgate"
  exit 1
fi
