#!/usr/bin/env bash
# install-reality.sh — 无交互一键部署：dokodemo-door + VLESS Reality + 白名单防偷跑
# 适用：Ubuntu 18.04/20.04/22.04；以 root 运行；参数通过环境变量传入
set -euo pipefail
export LC_ALL=C

: "${DOMAIN:?请以环境变量 DOMAIN=example.com 指定伪装域名}"
UUID="${UUID:-$(cat /proc/sys/kernel/random/uuid)}"
SHORT_ID="${SHORT_ID:-$(head -c4 /dev/urandom | hexdump -v -e '/1 "%02x"')}"
REAL_PORT="${REAL_PORT:-443}"
DOC_PORT="${DOC_PORT:-4431}"
ENABLE_UFW="${ENABLE_UFW:-1}"
SETCAP="${SETCAP:-1}"
SKIP_INSTALL="${SKIP_INSTALL:-0}"
PRINT_IP="${PRINT_IP:-1}"

XRAY_BIN="/usr/local/bin/xray"
CONFIG_PATH="/usr/local/etc/xray/config.json"
SERVICE_FILE="/etc/systemd/system/xray.service"
ACCESS_LOG="/var/log/xray/access.log"
ERROR_LOG="/var/log/xray/error.log"

log() { printf "\033[1;32m[+] %s\033[0m\n" "$*"; }
warn(){ printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err() { printf "\033[1;31m[x] %s\033[0m\n" "$*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || err "请以 root 运行（sudo -i）。"; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || err "缺少命令：$1"; }

require_root
log "安装基础工具 ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget nano unzip socat uuid-runtime ca-certificates libcap2-bin ufw >/dev/null

if [[ "${SKIP_INSTALL}" != "1" ]]; then
  log "安装/更新 Xray ..."
  bash <(curl -Ls https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) >/dev/null 2>&1
else
  log "跳过 Xray 安装（SKIP_INSTALL=1）"
fi

require_cmd "$XRAY_BIN"
log "Xray 版本：$($XRAY_BIN version | head -n1)"

log "生成 Reality X25519 密钥 ..."
KEY_RAW="$($XRAY_BIN x25519)"
PRIVATE_KEY="$(awk -F': ' '/Private key/{print $2}' <<<"$KEY_RAW")"
PUBLIC_KEY="$(awk  -F': ' '/Public key/{print $2}'  <<<"$KEY_RAW")"
[[ -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" ]] || err "生成 Reality 密钥失败"

log "写入配置：$CONFIG_PATH"
mkdir -p "$(dirname "$CONFIG_PATH")" /var/log/xray
cat > "$CONFIG_PATH" <<EOF
{
  "log": { "loglevel": "info", "access": "$ACCESS_LOG", "error": "$ERROR_LOG" },
  "inbounds": [
    {
      "tag": "dokodemo-in",
      "port": $REAL_PORT,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1", "port": $DOC_PORT, "network": "tcp" },
      "sniffing": { "enabled": true, "destOverride": ["tls"], "routeOnly": true }
    },
    {
      "tag": "vless-reality-in",
      "listen": "127.0.0.1",
      "port": $DOC_PORT,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$UUID" } ], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$DOMAIN:443",
          "serverNames": ["$DOMAIN"],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": ["$SHORT_ID"]
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
      { "type": "field", "inboundTag": ["dokodemo-in"], "domain": ["$DOMAIN"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["dokodemo-in"], "outboundTag": "block" }
    ]
  }
}
EOF
chmod 644 "$CONFIG_PATH"
touch "$ACCESS_LOG" "$ERROR_LOG"; chmod 640 "$ACCESS_LOG" "$ERROR_LOG"

if [[ "$SETCAP" == "1" ]]; then
  log "赋予 cap_net_bind_service ..."
  setcap 'cap_net_bind_service=+ep' "$XRAY_BIN" || true
  if ! getcap "$XRAY_BIN" | grep -q cap_net_bind_service; then
    warn "setcap 失败，改为以 root 运行 xray.service"
    if [[ -f "$SERVICE_FILE" ]]; then sed -i '/^User=/d' "$SERVICE_FILE"; fi
  fi
fi

if ss -lntp | awk '{print $4" "$7}' | grep -q ":${REAL_PORT} "; then
  warn "检测到 ${REAL_PORT}/tcp 已被占用："
  ss -lntp | awk '{print $4" "$7}' | grep ":${REAL_PORT} " || true
fi

log "启动 Xray ..."
systemctl daemon-reload
systemctl enable --now xray
sleep 1
systemctl is-active --quiet xray || { journalctl -u xray --no-pager -n 50 >&2; err "xray.service 启动失败"; }

if [[ "$ENABLE_UFW" == "1" && -x "$(command -v ufw)" ]]; then
  log "UFW 放行 ${REAL_PORT}/tcp ..."
  ufw allow "${REAL_PORT}/tcp" >/dev/null || true
fi

log "监听检查："
ss -lntp | grep -E ":(${REAL_PORT}|${DOC_PORT})\b" || true

PUBIP="(跳过获取)"; [[ "$PRINT_IP" == "1" ]] && PUBIP="$(curl -s --max-time 3 https://api.ipify.org || echo unknown)"
cat <<EOF

========== 已完成部署（无交互版） ==========
服务器地址   : ${PUBIP}  (或你自有接入域名/IP)
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
1) “地址/IP”填本机IP或接入用域名；SNI 必须填 ${DOMAIN}
2) PublicKey 填上面的“Reality 公钥”，ShortID 填 “${SHORT_ID}”
3) 若连不通，先看：ss -lntp | grep :${REAL_PORT} 以及 journalctl -u xray -f
EOF
