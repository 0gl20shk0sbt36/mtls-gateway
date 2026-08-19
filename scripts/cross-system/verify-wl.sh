#!/usr/bin/env bash
# 跨系统 E2E 复跑: 方向 W-L (Windows gw 100.64.0.2 + Linux relay)
# 前置: win2 gw 常驻 (schtasks mtls-gw2, bind 100.64.0.2, server.crt SAN 含双 IP)
#       Windows echo 9087 (schtasks mtls-echo); 本机共享 certs /tmp/e2e/win2/certs
set -euo pipefail

GW_IP="${GW_IP:-100.64.0.2}"
ADMIN_PWD="${ADMIN_PWD:-dandan070804}"
RELAY_PORT=28190
LOCAL_PORT=48191
CERTS=/tmp/e2e/win2/certs
RELAY_BIN=/tmp/e2e/m2/mtls-relay2
CA=/tmp/e2e/win2/ca.crt

fail() { echo "✘ $*"; exit 1; }
ok()   { echo "✔ $*"; }

[ -f "$RELAY_BIN" ] || fail "relay 二进制不存在: $RELAY_BIN (先 go build)"
[ -d "$CERTS" ] || fail "certs 目录不存在: $CERTS"

# 1. 起 relay (指向 Windows gw)
cat > /tmp/e2e/cross-wl.json <<EOF
{
  "server_addr": "$GW_IP:29998",
  "admin_addr": "$GW_IP:29999",
  "listen_host": "127.0.0.1",
  "server_ca": "$CA",
  "tunnels": []
}
EOF
pkill -f "mtls-relay2 -config /tmp/e2e/cross-wl.json" 2>/dev/null || true
sleep 0.5
"$RELAY_BIN" -config /tmp/e2e/cross-wl.json -source dir -source-arg "$CERTS" -show-all -listen-admin 127.0.0.1:$RELAY_PORT >/tmp/e2e/wl-relay.log 2>&1 &
RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null || true' EXIT
sleep 1.2

# 2. admin 验证 (跨系统 mTLS 认证)
VERIFY=$(curl -s -X POST http://127.0.0.1:$RELAY_PORT/api/verify -H "Content-Type: application/json" \
  -d "{\"cert_id\":\"admin\",\"load_pwd\":\"$ADMIN_PWD\"}")
echo "$VERIFY" | grep -q '"admin":true' || fail "admin 验证失败: $VERIFY"
ok "admin 证书验证 (跨系统 mTLS) → admin=true"

# 3. 签发无密码业务证书 (经 admin 桥) — 幂等: 已存在则复用
NAME="cross-b"
if ! ls "$CERTS/$NAME/cert.pem" >/dev/null 2>&1; then
  ISSUE=$(curl -s -X POST http://127.0.0.1:$RELAY_PORT/api/admin/issue -H "Content-Type: application/json" \
    -d "{\"cert_id\":\"admin\",\"load_pwd\":\"$ADMIN_PWD\",\"name\":\"$NAME\",\"purposes\":[\"svc-a\"],\"no_password\":true,\"days\":30}")
  echo "$ISSUE" | grep -q '"serial"' || fail "签发失败: $ISSUE"
  # 拷证书到共享源 (签发输出在 Windows issued/, 经挂载点)
  mkdir -p "$CERTS/$NAME"
  cp -f /mnt/host-temporary/mtls-e2e/win2/issued/$NAME/cert.pem /mnt/host-temporary/mtls-e2e/win2/issued/$NAME/key.pem "$CERTS/$NAME/"
  ok "签发无密码业务证书 $NAME"
fi

# 4. 建隧道 + 转发
curl -s -X POST http://127.0.0.1:$RELAY_PORT/api/tunnels -H "Content-Type: application/json" \
  -d "{\"service\":\"svc-a\",\"cert_id\":\"$NAME\",\"locals\":{\":29991\":\":$LOCAL_PORT\"}}" | grep -q '"ok":true' || fail "建隧道失败"
sleep 1.5
CODE=$(curl -s -o /tmp/e2e/wl-fwd.html -w "%{http_code}" http://127.0.0.1:$LOCAL_PORT/)
[ "$CODE" = "200" ] || fail "转发失败: HTTP $CODE"
ok "转发: Linux :$LOCAL_PORT → Windows gw :29991 → Windows echo 9087 = HTTP 200"

# 5. mTLS 壳
BARE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 https://$GW_IP:29992/ || true)
[ "$BARE" = "000" ] || fail "无证书直连应被拒, got $BARE"
ok "mTLS: 无证书直连 = 000 (握手拒绝)"

BADCERT=$(curl -sk --cert /tmp/mtls-e2e-ci/bad-client.pem --key /tmp/mtls-e2e-ci/bad-client.pem -o /dev/null -w "%{http_code}" --connect-timeout 5 https://$GW_IP:29992/ || true)
[ "$BADCERT" = "000" ] || fail "坏 CA 证书应被拒, got $BADCERT"
ok "mTLS: 错误 CA 证书 = 000 (拒绝)"

# 6. 清理
curl -s -X DELETE "http://127.0.0.1:$RELAY_PORT/api/tunnels/svc-a" >/dev/null
ok "W-L 全部验证通过 ✅"
