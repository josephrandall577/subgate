# SubGate — 订阅反代网关

订阅链接的"反向代理防火墙"。单个 Go 二进制同时提供两个监听：**网关**（数据面，过滤链+反代）与**管理后台**（控制面，隐藏路径）。无数据库，全部文件存储于 `data/`。

## 快速开始

服务器上一条命令（从 GitHub 取源码 → 交互配置 → Docker 镜像内编译 → 启动容器 → 打印访问信息）。依赖 git 与 Docker，**缺 Docker 时会自动执行 get.docker.com 官方脚本安装**：

```bash
curl -fsSL https://raw.githubusercontent.com/josephrandall577/subgate/main/deploy.sh | bash
```

源码默认落在 `~/subgate`（可用 `SUBGATE_DIR=/opt/subgate` 覆盖；`SUBGATE_REF` 指定分支/标签）。
随机管理员密码与后台路径打印在末尾并存入 `data/deploy-info.txt`。

后续更新：`cd ~/subgate && ./update.sh`（拉新代码→重建→重启→健康检查，`data/` 内机密与配置保留）。

手动运行：`go build -o subgate . && ./subgate -data data`（首次启动自动生成管理员密码并打印）。

## Cloudflare Tunnel 部署（推荐场景）

1. Zero Trust 里将订阅域名指向 `http://localhost:18080`（网关端口）。
2. 设置中"真实IP头"保持默认 `CF-Connecting-IP`，"受信代理网段"保持 `127.0.0.0/8,::1/128`（cloudflared 从本机回源）。
3. 管理后台只绑 `127.0.0.1`，通过第二条隧道或 SSH 端口转发访问 `http://127.0.0.1:18081/<随机路径>/`。

## 过滤链（命中即短路）

真实IP还原 → **IP白名单（命中直接反代，架构上最高优先级）** → IP黑名单 → 云厂商IP（阿里/腾讯/华为/字节/GCP/AWS/Azure/DO/UCloud/Vultr，ASN 数据源每7天自动刷新，失败保留旧数据）→ UA四层（白名单豁免 > 空UA拦截 > 内置规则 > 自定义封禁）→ 非订阅路径 → 按IP限速（默认 20次/分，突发5）→ 反代上游。

## 语义决策（按需求文档四点明确）

- **拦截响应策略**：全局统一为**静默断连**（0字节），仅限速返回 429（规范要求限流状态码）。
- **Token黑名单 = 仅监控**：只从分析统计中排除并记录"今日被哪些IP拉取"，**不拦截**，UI 已注明。
- **白名单最高优先**：代码结构上先判白名单直达反代，不依赖拦截顺序。
- **云IP库刷新失败**：按厂商原子替换，任一厂商抓取失败则保留其旧网段。

## 文件布局

```text
data/secrets.json     部署期机密（账号、bcrypt密码、随机后台路径）— 升级不覆盖
data/config.json      运行期配置（上游、名单、UA规则、限速…）— 后台改动立即热生效
data/cloud_ips.json   云厂商CIDR缓存
data/logs/access-YYYY-MM-DD.jsonl   按天访问日志（JSONL，导入/导出/清理均基于此；保留5天，每小时自动清理过期文件）
```

其余说明：Token 优先从查询参数 `token` 提取，否则取路径末段（`/prefix/TOKEN` 形态，须为≥16位字母数字`-_`）；真实IP头为逗号列表时取最右值（防最左伪造，CF-Connecting-IP 单值不受影响）；上游 DNS 依赖 Go 新建连接时的自然重解析（空闲连接 90s 回收）；证书到期信息通过对"证书监控域名"发起 TLS 握手获取（CF 场景查的即边缘证书）；自动申请证书未实现——CF Tunnel 场景 TLS 由 Cloudflare 终结，无需本机证书。
