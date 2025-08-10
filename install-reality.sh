#!/usr/bin/env bash
# install-reality.sh — 混合模式一键部署：dokodemo-door + VLESS Reality + SNI 白名单防偷跑
# 适用：Debian/Ubuntu（18.04/20.04/22.04/12），root 运行
# 变量：DOMAIN(必)、UUID、SHORT_ID、REAL_PORT=443、DOC_PORT=4431、ENABLE_UFW=1、SETCAP=1、SKIP_INSTALL=0、PRINT_IP=1、CONFIRM=auto|yes|no、DRY_RUN=0
set -euo pipefail
export LC_ALL=C

log()  { printf "\033[1;32m[+] %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err()  { printf "\033[1;31m[x] %s\033[0m\n" "$*" >&2; exit 1; }
is_tty(){ [[ -t 0 ]]; }  # 是否交互终端
require_root() { [[ $EUID -eq 0 ]] || err "请以 root 运行（sudo -i）。"; }
require_cmd()  { command -v "$1" >/dev/null 2>&1 || err "缺少命令：$1"; }
esc() { local s=${1//\\/\\\\}; s=${s//\//\\/}; s=${s//&/\\&}; printf '%s' "$s"; }

DOMAIN="${DOMAIN:-}"; UUID="${UUID:-}"; SHORT_ID="${SHORT_ID:-}"
REAL_PORT="${REAL_PORT:-443}"; DOC_PORT="${DOC_PORT:-4431}"
ENABLE_UFW="${ENABLE_UFW:-1}"; SETCAP="${SETCAP:-1}"
SKIP_INSTALL="${SKIP_INSTALL:-0}"; PRINT_IP="${PRINT_IP:-1}"
CONFIRM="${CONFIRM:-auto}"; DRY_RUN="${DRY_RUN:-0}"

XRAY_BIN="/usr/local/bin/xray"
CONFIG_PATH="/usr/local/etc/xray/config.json"
SERVICE_FILE="/etc/systemd/system/xray.service"
ACCESS_LOG="/var/log/xray/access.log"; ERROR_LOG="/var/log/xray/error.log"

require_root

# 参数收集（混合：有变量走无交互；缺变量且是 TTY 就问一次）
if [[ -z "$DOMAIN" ]]; then
  if is_tty; then
    read -rp "请输入 *伪装域名* (如: junjies.com): " DOMAIN
  else
    err "未提供 DOMAIN。示例：DOMAIN=junjies.com bash <(curl -fsSL https://raw.githubusercontent.com/<user>/<repo>/main/install-reality.sh)"
  fi
fi
[[ -z "$UUID" ]] && UUID="$(cat /proc/sys/kernel/random/uuid)"
[[ -z "$SHORT_ID" ]] && SHORT_ID="$(head -c4 /dev/urandom | hexdump -v -e '/1 \"%02x\"')"
if is_tty; then
  read -rp "自定义 ShortID (默认: $SHORT_ID，回车保持): " _i; [[ -n "${_i:-}" ]] && SHORT_ID="$_i"
  read -rp "自定义 UUID   (默认: $UUID，回车保持): "   _j; [[ -n "${_j:-}" ]] && UUID="$_j"
fi

# 预览与确认
if [[ "$CONFIRM" == "yes" ]] || { [[ "$CONFIRM" == "auto" ]] && is_tty; }; then
  cat <<PREVIEW

===== 参数预览 =====
伪装域名 : $DOMAIN
UUID     : $UUID
ShortID  : $SHORT_ID
入口端口 : $REAL_PORT
内网端口 : $DOC_PORT
UFW放行  : $ENABLE_UFW
setcap   : $SETCAP
SKIP安装 : $SKIP_INSTALL
DRY_RUN  : $DRY_RUN
====================
PREVIEW
  read -rp "确认无误回车继续，Ctrl+C 取消 ..." _
fi

# 环境与依赖
log "安装基础工具 ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget nano unzip socat uuid-runtime ca-certificates libcap2-bin ufw >/dev/null

# 安装/升级 Xray
if [[ "$SKIP_INSTALL" != "1" ]]; then
  log "安装/更新 Xray ..."
  bash <(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) >/dev/null 2>&1
else
  log "跳过 Xray 安装（SKIP_INSTALL=1）"
fi
require_cmd "$XRAY_BIN"
log "Xray 版本：$($XRAY_BIN version | head -n1)"

# Reality 密钥
log "生成 Reality X25519 密钥 ..."
KEY_RAW="$($XRAY_BIN x25519)"
PRIVATE_KEY="$(awk -F': ' '/Private key/{print $2}' <<<"$KEY_RAW")"
PUBLIC_KEY="$(awk  -F': ' '/Public key/{print $2}'  <<<"$KEY_RAW")"
[[ -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" ]] || err "生成 Reality 密钥失败"

# 生成配置并替换
log "生成配置模板 ..."
mkdir -p "$(dirname "$CONFIG_PATH")" /var/log/xray
TMP_CFG="$(mktemp)"
cat > "$TMP_CFG" <<'EOF'
{
  "log": { "loglevel": "info", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log" },
  "inbounds": [
    {
      "tag": "dokodemo-in",
      "port": REAL_PORT_REPLACE,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1", "port": DOC_PORT_REPLACE, "network": "tcp" },
      "sniffing": { "enabled": true, "destOverride": ["tls"], "routeOnly": true }
    },
    {
      "tag": "vless-reality-in",
      "listen": "127.0.0.1",
      "port": DOC_PORT_REPLACE,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "UUID_REPLACE" } ], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "DOMAIN_REPLACE:443",
          "serverNames": ["DOMAIN_REPLACE"],
          "privateKey": "PRIVATE_KEY_REPLACE",
          "shortIds": ["SHORT_ID_REPLACE"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["tls","http","quic"], "routeOnly": true }
    }
  ],
  "outbounds": [
    { "protocol": "freedom",  "tag": "direct" },
    { "protocol": "blackhole","tag": "block"  }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["dokodemo-in"], "domain": ["DOMAIN_REPLACE"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["dokodemo-in"], "outboundTag": "block" }
    ]
  }
}
EOF
sed -i "s/REAL_PORT_REPLACE/$(esc "$REAL_PORT")/g" "$TMP_CFG"
sed -i "s/DOC_PORT_REPLACE/$(esc "$DOC_PORT")/g"   "$TMP_CFG"
sed -i "s/UUID_REPLACE/$(esc "$UUID")/g"           "$TMP_CFG"
sed -i "s/DOMAIN_REPLACE/$(esc "$DOMAIN")/g"       "$TMP_CFG"
sed -i "s/PRIVATE_KEY_REPLACE/$(esc "$PRIVATE_KEY")/g" "$TMP_CFG"
sed -i "s/SHORT_ID_REPLACE/$(esc "$SHORT_ID")/g"   "$TMP_CFG"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN=1：仅预览 config.json，不写入/不重启服务："
  echo "----- /usr/local/etc/xray/config.json (preview) -----"
  cat "$TMP_CFG"
  rm -f "$TMP_CFG"
  exit 0
fi

install -m 0644 "$TMP_CFG" "$CONFIG_PATH"
rm -f "$TMP_CFG"
touch "$ACCESS_LOG" "$ERROR_LOG"; chmod 640 "$ACCESS_LOG" "$ERROR_LOG"

# 443 绑定能力：setcap 或 root
if [[ "$SETCAP" == "1" ]]; then
  log "赋予 cap_net_bind_service 能力 ..."
  setcap 'cap_net_bind_service=+ep' "$XRAY_BIN" || true
  if ! getcap "$XRAY_BIN" | grep -q cap_net_bind_service; then
    warn "setcap 失败，改为以 root 运行 xray.service"
    [[ -f "$SERVICE_FILE" ]] && sed -i '/^User=/d' "$SERVICE_FILE"
    if grep -q '^\[Service\]' "$SERVICE_FILE"; then
      awk '1; /^\[Service\]$/ && !p {print "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true"; p=1}' \
        "$SERVICE_FILE" >"${SERVICE_FILE}.tmp" && mv "${SERVICE_FILE}.tmp" "$SERVICE_FILE"
    fi
  fi
fi

# 端口占用提示
if ss -lntp | awk '{print $4" "$7}' | grep -q ":${REAL_PORT} "; then
  warn "检测到 ${REAL_PORT}/tcp 已被占用："
  ss -lntp | awk '{print $4" "$7}' | grep ":${REAL_PORT} " || true
  warn "如为 Nginx/Apache，请释放端口或改 REAL_PORT。"
fi

# 启动
log "启动/重载 Xray ..."
systemctl daemon-reload
systemctl enable --now xray
sleep 1
if ! systemctl is-active --quiet xray; then
  journalctl -u xray --no-pager -n 80 >&2
  err "xray.service 启动失败，请根据上面日志排查。"
fi

# 防火墙
if [[ "$ENABLE_UFW" == "1" ]] && command -v ufw >/dev/null 2>&1; then
  log "UFW 放行 ${REAL_PORT}/tcp ..."
  ufw allow "${REAL_PORT}/tcp" >/dev/null || true
fi

# 输出
log "监听检查："
ss -lntp | grep -E ":(${REAL_PORT}|${DOC_PORT})\b" || true
PUBIP="(跳过获取)"; [[ "$PRINT_IP" == "1" ]] && PUBIP="$(curl -s --max-time 3 https://api.ipify.org || echo unknown)"
cat <<EOF

========== 部署完成 ==========
服务器地址   : ${PUBIP}  (或你的接入域名/IP)
入口端口     : ${REAL_PORT}
协议         : VLESS (Reality over TCP)
UUID         : ${UUID}
加密/流控    : none / reality
-------------------------------------------
Reality 公钥 : ${PUBLIC_KEY}
Reality 短ID : ${SHORT_ID}
SNI (server) : ${DOMAIN}
指纹         : chrome / firefox
-------------------------------------------
配置文件     : ${CONFIG_PATH}
服务         : systemctl status xray
日志         : journalctl -u xray -f
===========================================

客户端要点：
1) “地址/IP”填本机IP或接入域名；SNI 必须填 ${DOMAIN}
2) PublicKey 填上面的“Reality 公钥”，ShortID 填 “${SHORT_ID}”
3) 若连不通，先看：ss -lntp | grep :${REAL_PORT} 以及 journalctl -u xray -f
EOF
