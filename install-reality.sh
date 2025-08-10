#!/usr/bin/env bash
# install-reality.sh — 自动部署 VLESS + Reality (dokodemo-door 白名单版)

set -euo pipefail
export LC_ALL=C

### === 0. 交互式收集基础信息 ====================================== ###
read -rp "请输入 *伪装域名* (如: junjies.com): " DOMAIN
read -rp "请确认该域名 A 记录已指向本机 (回车继续) " _
read -rp "自定义 ShortID (1-16 字符，留空则随机): " SHORT_ID
read -rp "自定义 UUID (留空则随机): " USER_UUID

[[ -z "$SHORT_ID" ]] && SHORT_ID=$(head -c4 /dev/urandom | hexdump -e '"%02x"')
[[ -z "$USER_UUID" ]] && USER_UUID=$(cat /proc/sys/kernel/random/uuid)

# 端口可改；如需自定义请同步改 ROUTE_PORT & DOC_PORT
REAL_PORT=443
DOC_PORT=4431

echo -e "\n===== 参数预览 ====="
printf "伪装域名:  %s\n"   "$DOMAIN"
printf "UUID:      %s\n"   "$USER_UUID"
printf "ShortID:   %s\n"   "$SHORT_ID"
printf "入口端口:  %s\n"   "$REAL_PORT"
printf "内网端口:  %s\n\n" "$DOC_PORT"
read -rp "如无误请回车继续，否则 Ctrl+C 退出 "

### === 1. 基础工具 & 更新 ========================================= ###
echo "[1/9] 更新系统并安装依赖 ..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq curl wget nano socat setcap uuid-runtime ufw

### === 2. 安装 Xray Core ========================================= ###
echo "[2/9] 安装 / 更新 Xray ..."
bash <(curl -Ls https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) >/dev/null 2>&1

### === 3. 生成 Reality 密钥对 ==================================== ###
echo "[3/9] 生成 Reality X25519 密钥 ..."
KEY_RAW=$(xray x25519)
PRIVATE_KEY=$(grep "Private key" <<<"$KEY_RAW" | awk '{print $3}')
PUBLIC_KEY=$(grep  "Public key"  <<<"$KEY_RAW" | awk '{print $3}')
echo "  PrivateKey: $PRIVATE_KEY"
echo "  PublicKey : $PUBLIC_KEY"

### === 4. 写入配置文件 =========================================== ###
echo "[4/9] 写入 /usr/local/etc/xray/config.json ..."
CONFIG_PATH="/usr/local/etc/xray/config.json"
mkdir -p /usr/local/etc/xray

cat > "$CONFIG_PATH" <<EOF
{
  "log": {
    "loglevel": "info",
    "access": "/var/log/xray/access.log",
    "error":  "/var/log/xray/error.log"
  },
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
      "settings": {
        "clients": [ { "id": "$USER_UUID" } ],
        "decryption": "none"
      },
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
      {
        "type": "field",
        "inboundTag": ["dokodemo-in"],
        "domain": ["$DOMAIN"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundTag": ["dokodemo-in"],
        "outboundTag": "block"
      }
    ]
  }
}
EOF

### === 5. 赋予 443 绑定能力 (cap_net_bind_service) ================= ##
echo "[5/9] 设置二进制绑定特权端口能力 ..."
setcap 'cap_net_bind_service=+ep' /usr/local/bin/xray
getcap /usr/local/bin/xray | grep cap_net_bind_service >/dev/null || {
  echo "Setcap 失败，改用 root 运行 ..."
  sed -i '/^User=/d' /etc/systemd/system/xray.service
}

### === 6. 创建日志目录 ========================================== ###
mkdir -p /var/log/xray
touch /var/log/xray/{access,error}.log
chmod 640 /var/log/xray/*

### === 7. 重载 systemd 并启动 Xray ================================ ###
echo "[6/9] 重启 xray.service ..."
systemctl daemon-reload
systemctl enable --now xray

### === 8. UFW / 安全组放行 443 ================================== ###
echo "[7/9] 设置防火墙 ..."
ufw allow $REAL_PORT/tcp >/dev/null || true

### === 9. 自检监听与状态 ======================================== ###
echo "[8/9] 自检端口监听 ..."
ss -lntp | grep ":$REAL_PORT" | grep xray >/dev/null && echo "Xray 已监听 $REAL_PORT" || {
  echo "Xray 未监听 $REAL_PORT，请检查 systemctl status xray"; exit 1; }

echo "[9/9] 部署完成！\n"

cat <<INFO
================= 客户端参数 =================
地址 / 域名 : $(curl -s https://api.ipify.org)  (或 $DOMAIN)
端口        : $REAL_PORT
协议        : VLESS
UUID        : $USER_UUID
加密        : none
传输层      : tcp
流控        : reality
---------------------------------------------
PublicKey   : $PUBLIC_KEY
ShortID     : $SHORT_ID
SNI         : $DOMAIN
指纹        : chrome / firefox
=============================================
如需查看实时日志：  journalctl -u xray -f
INFO
