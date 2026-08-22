#!/usr/bin/env bash
# WebUI E2E 环境搭建(管理服务拆分后双进程): 生成 CA/证书/配置, 起 admin+gw+echo+relay, 输出 WEBUI_URL
# 用法: ./setup.sh [工作目录]   (默认 /tmp/mtls-e2e-ci; 每次全新重建, 不保留旧环境)
# 注意: 管理拆分后签发/吊销在 mtls-admin 进程, 网关是只读数据面; 变更后经
#   gateway_reload_addr 调网关 /admin/reload 热重载 — 见下方"两阶段 admin"注释。
set -euo pipefail
D="${1:-/tmp/mtls-e2e-ci}"
# 先解析脚本绝对路径(必须在 cd "$D" 之前: 否则相对路径调用时 BASH_SOURCE 失效)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
# 清理旧环境(端口占用/残留文件), 保证可重复运行
for port in 57087 57090 57091 57092 57093 57097 57098 57099 57991; do
  fuser -k "${port}/tcp" 2>/dev/null || true
done
rm -rf "$D"
mkdir -p "$D/certs"
cd "$D"

echo "repo: $REPO"

# ---- 1. 构建二进制(含 mtls-admin: 管理拆分后签发/吊销在管理进程) ----
(cd "$REPO" && go build -o "$D/mtls-gw" ./cmd/mtls-gw && go build -o "$D/mtls-admin" ./cmd/mtls-admin && go build -o "$D/mtls-gw-cli" ./cmd/mtls-gw-cli && go build -o "$D/mtls-relay" ./cmd/mtls-relay)

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
# 权限预检(网关/管理启动时 mode&0o007==0 禁 world)要求私钥禁 world; openssl 已 0600, 防御式确保
chmod 600 ca.key server.key

# ---- 3. gw + admin 共享配置(双进程读同一 config.toml, 各取所需字段) ----
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
info_listen = ":57098"
reload_listen = ":57097"
admin_listen = ":57099"
log_file = "$D/gw-events.log"
access_log_file = "$D/gw-access.log"
stdout_log_file = "$D/gw-stdout.log"

roles = ["svc-a", "other"]

[[mappings]]
id = "svc-a-main"
listen = ":57091"
target = "http://127.0.0.1:57087"

[[mappings]]
id = "svc-a-admin"
listen = ":57091/admin"
target = "http://127.0.0.1:57087/"

[[mappings]]
id = "any-open"
listen = ":57092"
target = "http://127.0.0.1:57087"

[[mappings]]
id = "other-only"
listen = ":57093"
target = "http://127.0.0.1:57087"

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
python3 -m http.server 57087 --bind 127.0.0.1 >/dev/null 2>&1 &
echo $! > echo.pid

# ---- 5. 两阶段 admin: 先起管理进程(此时 reload 证书未签发, reload 客户端降级为 nil, 不影响签发) ----
"$D/mtls-admin" -config "$D/gw.toml" > admin.log 2>&1 &
echo $! > admin.pid
sleep 1

# ---- 6. 签发证书: reload-admin(供 admin 调网关 reload, 明文私钥) + admin(加密) + e2e-a ----
"$D/mtls-gw-cli" issue reload-admin --sock "$D/gw.sock" --purpose mtls-superadmin --days 365 >/dev/null 2>&1
"$D/mtls-gw-cli" issue admin --sock "$D/gw.sock" --purpose mtls-superadmin --password ci-admin-pw --days 365 >/dev/null 2>&1
"$D/mtls-gw-cli" issue e2e-a --sock "$D/gw.sock" --purpose svc-a --days 365 >/dev/null 2>&1
mkdir -p "$D/certs/admin" "$D/certs/e2e-a"
# admin 私钥转 legacy 加密(与真实演示一致: 私钥需密码, 任意密码不能通过验证)
openssl rsa -in "$D/issued/admin/key.pem" -traditional -aes256 -passout pass:ci-admin-pw -out "$D/issued/admin/key.enc.pem" 2>/dev/null
mv -f "$D/issued/admin/key.enc.pem" "$D/issued/admin/key.pem"
cp -f "$D/issued/admin/cert.pem" "$D/issued/admin/key.pem" "$D/certs/admin/"
cp -f "$D/issued/e2e-a/cert.pem" "$D/issued/e2e-a/key.pem" "$D/certs/e2e-a/"

# ---- 7. 追加 reload 配置(证书已签发; 重启 admin 后 reload 客户端生效) ----
# 注意: 必须插在 [[mappings]] 之前 — TOML 顶级键放在 [[services]] 数组之后会被
# 当成最后一个 service 的字段静默吞掉(phase-2 admin 读不到 reload 配置)。
awk -v r1='gateway_reload_addr = "127.0.0.1:57097"' \
    -v r2="reload_cert = \"$D/issued/reload-admin/cert.pem\"" \
    -v r3="reload_key = \"$D/issued/reload-admin/key.pem\"" \
    '{ if ($0 == "[[mappings]]") { print r1; print r2; print r3 } print }' "$D/gw.toml" > "$D/gw.toml.new" && mv "$D/gw.toml.new" "$D/gw.toml"

# ---- 8. 重启 admin(reload 证书已签发 → 重建 reload 客户端, 变更后自动调网关热重载) ----
kill "$(cat admin.pid)" 2>/dev/null || true
sleep 1
"$D/mtls-admin" -config "$D/gw.toml" > admin.log 2>&1 &
echo $! > admin.pid
sleep 1

# ---- 9. 起 gw(在签发之后: 启动全量载入 DB, admin/e2e-a/reload-admin 均在册; 后续变更靠自动 reload) ----
"$D/mtls-gw" -config "$D/gw.toml" > gw.log 2>&1 &
echo $! > gw.pid
sleep 1

# 坏 CA 客户端证书(M4: 错误 CA 签发的证书应被服务器拒绝)
if [ ! -f bad-client.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout bad-ca.key -out bad-ca.crt -days 3650 -subj "/CN=e2e-ci-bad-ca" 2>/dev/null
  openssl req -new -newkey rsa:2048 -nodes -keyout bad-client.key -out bad-client.csr -subj "/CN=bad-client" 2>/dev/null
  openssl x509 -req -in bad-client.csr -CA bad-ca.crt -CAkey bad-ca.key -days 365 -out bad-client.crt 2>/dev/null
  cat bad-client.crt bad-client.key > bad-client.pem
  rm -f bad-client.csr
fi

# ---- 10. relay 配置 + 启动 ----
cat > relay.json <<EOF
{
  "server_addr": "127.0.0.1:57098",
  "admin_addr": "127.0.0.1:57099",
  "listen_host": "127.0.0.1",
  "server_ca": "$D/ca.crt",
  "cert_dir": "$D/certs",
  "tunnels": []
}
EOF
"$D/mtls-relay" -config "$D/relay.json" -source dir -source-arg "$D/certs" -show-all -listen-admin 127.0.0.1:57090 > relay.log 2>&1 &
echo $! > relay.pid
sleep 1

echo "WEBUI_URL=http://127.0.0.1:57090/"
echo "ADMIN_PWD=ci-admin-pw"
echo "E2E_DIR=$D"
