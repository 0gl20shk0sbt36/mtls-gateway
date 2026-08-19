#!/usr/bin/env bash
# WebUI E2E 环境搭建: 生成 CA/证书/配置, 起 gw+echo+relay, 输出 WEBUI_URL
# 用法: ./setup.sh [工作目录]   (默认 /tmp/mtls-e2e-ci; 每次全新重建, 不保留旧环境)
set -euo pipefail
D="${1:-/tmp/mtls-e2e-ci}"
# 清理旧环境(端口占用/残留文件), 保证可重复运行
for port in 46987 46990 46991 46992 46993 46998 46999 47991; do
  fuser -k "${port}/tcp" 2>/dev/null || true
done
rm -rf "$D"
mkdir -p "$D/certs"
cd "$D"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
echo "repo: $REPO"

# ---- 1. 构建二进制(CI 里 Go 可用; 本地也可直接用) ----
(cd "$REPO" && go build -o "$D/mtls-gw" ./cmd/mtls-gw && go build -o "$D/mtls-gw-cli" ./cmd/mtls-gw-cli && go build -o "$D/mtls-relay" ./cmd/mtls-relay)

# ---- 2. CA + 服务器证书 ----
if [ ! -f ca.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 -subj "/O=e2e-ci/OU=e2e-ci/CN=e2e-ci-ca" 2>/dev/null
fi
if [ ! -f server.crt ]; then
  openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/O=e2e-ci/CN=mtls-e2e-ci-gw" 2>/dev/null
  printf "subjectAltName=IP:127.0.0.1,DNS:localhost\n" > san.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -days 3650 -out server.crt -extfile san.ext 2>/dev/null
  rm -f server.csr san.ext
fi

# ---- 3. gw 配置(固定高位端口, 避免冲突) ----
cat > gw.toml <<EOF
bind_host = "127.0.0.1"
db = "$D/gw.db"
config_mode = "mutable"
admin_role = "mtls-superadmin"
ca = "$D/ca.crt"
ca_key = "$D/ca.key"
server_cert = "$D/server.crt"
server_key = "$D/server.key"
cert_dir = "$D/issued"
sock_path = "$D/gw.sock"
org = "e2e-ci"
ou = "e2e-ci"
require_ip_bind = false
info_listen = ":46998"
admin_listen = ":46999"
log_file = "$D/gw-events.log"
access_log_file = "$D/gw-access.log"

roles = ["svc-a", "other"]

[[mappings]]
id = "svc-a-main"
listen = ":46991"
target = "http://127.0.0.1:46987"

[[mappings]]
id = "svc-a-admin"
listen = ":46991/admin"
target = "http://127.0.0.1:46987/"

[[mappings]]
id = "any-open"
listen = ":46992"
target = "http://127.0.0.1:46987"

[[mappings]]
id = "other-only"
listen = ":46993"
target = "http://127.0.0.1:46987"

[[services]]
name = "svc-a"
channels = ["svc-a-main", "svc-a-admin"]
roles = ["svc-a"]

[[services]]
name = "any-svc"
channels = ["any-open"]
roles = ["any"]

[[services]]
name = "other-svc"
channels = ["other-only"]
roles = ["other"]
EOF

# ---- 4. echo 后端(python) ----
python3 -m http.server 46987 --bind 127.0.0.1 >/dev/null 2>&1 &
echo $! > echo.pid

# ---- 5. 起 gw ----
"$D/mtls-gw" -config "$D/gw.toml" > gw.log 2>&1 &
echo $! > gw.pid
sleep 1

# ---- 6. 签发证书: admin(加密) + e2e-a ----
"$D/mtls-gw-cli" issue admin --sock "$D/gw.sock" --purpose mtls-superadmin --password ci-admin-pw --days 365 >/dev/null 2>&1
"$D/mtls-gw-cli" issue e2e-a --sock "$D/gw.sock" --purpose svc-a --days 365 >/dev/null 2>&1
mkdir -p "$D/certs/admin" "$D/certs/e2e-a"
# admin 私钥转 legacy 加密(与真实演示一致: 私钥需密码, 任意密码不能通过验证)
openssl rsa -in "$D/issued/admin/key.pem" -traditional -aes256 -passout pass:ci-admin-pw -out "$D/issued/admin/key.enc.pem" 2>/dev/null
mv -f "$D/issued/admin/key.enc.pem" "$D/issued/admin/key.pem"
cp -f "$D/issued/admin/cert.pem" "$D/issued/admin/key.pem" "$D/certs/admin/"
cp -f "$D/issued/e2e-a/cert.pem" "$D/issued/e2e-a/key.pem" "$D/certs/e2e-a/"

# 坏 CA 客户端证书(M4: 错误 CA 签发的证书应被服务器拒绝)
if [ ! -f bad-client.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout bad-ca.key -out bad-ca.crt -days 3650 -subj "/CN=e2e-ci-bad-ca" 2>/dev/null
  openssl req -new -newkey rsa:2048 -nodes -keyout bad-client.key -out bad-client.csr -subj "/CN=bad-client" 2>/dev/null
  openssl x509 -req -in bad-client.csr -CA bad-ca.crt -CAkey bad-ca.key -days 365 -out bad-client.crt 2>/dev/null
  cat bad-client.crt bad-client.key > bad-client.pem
  rm -f bad-client.csr
fi

# ---- 7. relay 配置 + 启动 ----
cat > relay.json <<EOF
{
  "server_addr": "127.0.0.1:46998",
  "admin_addr": "127.0.0.1:46999",
  "listen_host": "127.0.0.1",
  "server_ca": "$D/ca.crt",
  "tunnels": []
}
EOF
"$D/mtls-relay" -config "$D/relay.json" -source dir -source-arg "$D/certs" -show-all -listen-admin 127.0.0.1:46990 > relay.log 2>&1 &
echo $! > relay.pid
sleep 1

echo "WEBUI_URL=http://127.0.0.1:46990/"
echo "ADMIN_PWD=ci-admin-pw"
echo "E2E_DIR=$D"
