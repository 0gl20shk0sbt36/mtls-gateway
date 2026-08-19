#!/usr/bin/env bash
# 跨系统 E2E 复跑: 方向 L-W (Linux gw 100.64.0.1 + Windows relay)
# 前置: m2 gw 常驻 (bind 100.64.0.1, server.crt SAN 含双 IP); Linux echo 9087 (python http.server)
#       Windows relay (schtasks mtls-relay-lw, admin 28184, certs 源 D:\temporary\mtls-e2e\win2\certs)
# 本脚本在 Linux 执行, 通过 sshpass 操作 Windows relay API。
set -euo pipefail

WIN_IP="${WIN_IP:-100.64.0.2}"
WIN_USER=yyx
WIN_PASS="${WIN_PASS:-$(cat ~/.winpass 2>/dev/null || echo dandan070804)}"
RELAY_PORT=28184
LOCAL_PORT=48391
GW_IP=100.64.0.1
SSH="sshpass -p $WIN_PASS ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 $WIN_USER@$WIN_IP"

fail() { echo "✘ $*"; exit 1; }
ok()   { echo "✔ $*"; }

# 1. Windows relay 存活
$SSH "netstat -ano | Select-String \":$RELAY_PORT.*LISTENING\"" >/dev/null 2>&1 || fail "Windows relay :$RELAY_PORT 未监听 (schtasks /Run /TN mtls-relay-lw)"
ok "Windows relay :$RELAY_PORT 存活"

# 2. e2e-a 验证 (跨系统 mTLS 认证: Windows relay → Linux gw)
VERIFY=$($SSH "try { (Invoke-RestMethod -Uri http://127.0.0.1:$RELAY_PORT/api/verify -Method Post -ContentType 'application/json' -Body (@{cert_id='e2e-a'} | ConvertTo-Json)) | ConvertTo-Json -Depth 4 -Compress } catch { \$_.ErrorDetails.Message }")
echo "$VERIFY" | grep -q '"admin":false' || fail "e2e-a 验证失败: $VERIFY"
ok "e2e-a 证书验证 (跨系统 mTLS) → 服务发现成功"

# 3. 建隧道 + 转发 (Windows 本地路由 → Linux gw → Linux echo)
$SSH "Invoke-RestMethod -Uri http://127.0.0.1:$RELAY_PORT/api/tunnels -Method Post -ContentType 'application/json' -Body (@{service='svc-a'; cert_id='e2e-a'; locals=@{':39991'=':$LOCAL_PORT'}} | ConvertTo-Json) | Out-Null"
sleep 1.5
RESP=$($SSH "try { \$r = Invoke-WebRequest -Uri http://127.0.0.1:$LOCAL_PORT/ -UseBasicParsing -TimeoutSec 8; Write-Output ('HTTP ' + \$r.StatusCode + ' len=' + \$r.Content.Length) } catch { Write-Output ('ERR ' + \$_.Exception.Message) }")
echo "$RESP" | grep -q "HTTP 200" || fail "转发失败: $RESP"
ok "转发: Windows :$LOCAL_PORT → Linux gw :39991 → Linux echo 9087 = $RESP"

# 4. mTLS 壳 (Linux 侧直连 Linux gw)
BARE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 https://$GW_IP:39992/ || true)
[ "$BARE" = "000" ] || fail "无证书直连应被拒, got $BARE"
ok "mTLS: 无证书直连 = 000 (握手拒绝)"

WITHCERT=$(curl -sk --cert /tmp/e2e/win2/certs/e2e-a/cert.pem --key /tmp/e2e/win2/certs/e2e-a/key.pem -o /dev/null -w "%{http_code}" --connect-timeout 5 https://$GW_IP:39992/ || true)
[ "$WITHCERT" = "200" ] || fail "带证书直连应 200, got $WITHCERT"
ok "mTLS: 带 e2e-a 证书直连 = 200 (直连 mTLS 应用场景)"

# 5. 清理
$SSH "Invoke-RestMethod -Uri \"http://127.0.0.1:$RELAY_PORT/api/tunnels/svc-a\" -Method Delete | Out-Null" 2>/dev/null || true
ok "L-W 全部验证通过 ✅"
