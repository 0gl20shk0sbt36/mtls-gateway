# mtls-gw — Generic mTLS Gateway

A generic access gateway based on mTLS client certificates. Provides **device-level authentication + purpose-based routing** for self-hosted services. Not tied to any specific application — reuse it for any backend.

```
device (holds device cert)
  → [mtls-gw] (mTLS verify + IP check + authorization + routing)
      ├─ app-a → http://127.0.0.1:3080
      ├─ app-b → http://127.0.0.1:8081   (add one config line for each app)
      └─ /admin/* → management API (admin cert only)
```

---

## 1. Core Design

### 1.1 Cert = Identity, Database = Permissions (separation of concerns)

| Layer | Carries | Notes |
|-------|---------|-------|
| **Certificate** | Identity | serial (unique primary key) + SAN bound to device IP |
| **SQLite** | Permissions | serial → {name, purposes[], status, expires} |

- The certificate contains **no purpose/permission fields** — admin checks rely entirely on the database, never on cert CN/fields
- Purposes are a list: `admin` / `app-a` / any future purpose
- Revoking/changing permissions only touches the database — no re-issuing certificates

### 1.2 Verification Flow (per request)

```
1. TLS handshake → chain verification (ClientCAs = trusted CA pool)
   └─ minimum bar only: cert must be signed by a trusted CA, but that alone grants nothing
2. IP pre-check: cert SAN IP == source IP? mismatch → reject immediately (no DB access)
   └─ anti key-copy: cert copied to another device fails the source-IP check
3. In-memory lookup: serial → record (nanoseconds, zero I/O)
   ├─ serial not in DB → reject (signed by CA but unregistered = denied)
   ├─ status=revoked → reject
   └─ expired → reject
4. Authorize by purposes → route to backend
```

> Security model is a **double gate**: ① chain verification (CA-signed) ② database registration (serial in table).
> Either alone is insufficient — CA-signed but unregistered, or registered but not signed by this CA, both rejected.

### 1.3 Memory as Authority (performance)

- On startup, load all of SQLite → in-memory map (serial → record)
- **Request verification hits memory only** (nanosecond, no disk)
- Mutations (issue/revoke) update memory + persist to SQLite
- Small dataset (dozens of certs), no cache-consistency issues

### 1.4 Management Channels

| Channel | Use | Auth |
|---------|-----|------|
| Unix socket | local CLI | file mode 600 = direct admin |
| TCP (mTLS) | remote web panel (future) | admin-purpose cert |

### 1.5 Host/Origin Rewrite (no backend changes needed)

mtls-gw rewrites `Host` and `Origin` to the backend's loopback address:

```
browser request: Host: gw.example:9443, Origin: https://gw.example:9443
mtls-gw rewrite → Host: 127.0.0.1:3080, Origin: https://127.0.0.1:3080
backend trust fence: sees loopback → privileged methods pass naturally
```

→ **No backend source changes, upgrade-safe**

---

## 2. Deployment

### 2.1 Build

```bash
cd mtls-gateway
go build -o mtls-gw ./cmd/mtls-gw
go build -o mtls-gw-cli ./cmd/mtls-gw-cli
```

### 2.2 Install

```bash
sudo cp mtls-gw /usr/local/bin/
sudo cp mtls-gw-cli /usr/local/bin/
sudo mkdir -p /var/lib/mtls-gw/certs
sudo chown -R $(whoami):$(whoami) /var/lib/mtls-gw
sudo mkdir -p /etc/mtls-gw
```

### 2.3 Config `/etc/mtls-gw/config.json`

```json
{
  "admin_listen": "0.0.0.0:9444",
  "ca": "/etc/mtls-gw/ca.crt",
  "ca_key": "/etc/mtls-gw/ca.key",
  "server_cert": "/etc/mtls-gw/server.crt",
  "server_key": "/etc/mtls-gw/server.key",
  "cert_dir": "/var/lib/mtls-gw/certs",
  "sock_path": "/run/mtls-gw/mtls-gw.sock",
  "org": "my-org",
  "ou": "device",
  "default_days": 365,
  "admin_days": 30,
  "require_ip_bind": true,
  "backends": {
    "app-a": {
      "target": "http://127.0.0.1:3080",
      "listen": "0.0.0.0:9443"
    }
  }
}
```

- `backends`: **purpose → backend**, each with its own `listen` port
  - one port per purpose; a cert must have that purpose in its list or it gets 403
- `org` / `ou`: certificate O/OU fields (default "mtls-gw"/"device")
- `default_days` / `admin_days`: default validity for normal / admin certs
- `require_ip_bind`: require cert SAN IP to match source IP (default true; set false to allow unbound certs)

### 2.4 systemd service `/etc/systemd/system/mtls-gw.service`

```ini
[Unit]
Description=mtls-gw — generic mTLS gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<run-as-user>
WorkingDirectory=/home/<user>
RuntimeDirectory=mtls-gw
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/mtls-gw -config /etc/mtls-gw/config.json -db /var/lib/mtls-gw/mtls-gw.db -sock /run/mtls-gw/mtls-gw.sock
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-gw
```

---

## 3. CLI Usage

```bash
# issue a cert (local = direct admin via Unix socket)
mtls-gw-cli issue admin --purpose admin --ts-ip <mgmt-ip> --days 30
mtls-gw-cli issue device-1 --purpose app-a --ts-ip <device-ip> --days 365
mtls-gw-cli issue device-2 --purpose app-a,app-b --ts-ip <device-ip>   # multi-purpose

# revoke
mtls-gw-cli revoke <serial>

# list certs
mtls-gw-cli list

# health
mtls-gw-cli health

# custom socket path
mtls-gw-cli --sock /run/mtls-gw/mtls-gw.sock list
```

**admin rule**: a cert whose purposes include `admin` is **admin-only**:
- `--purpose admin,dsh` → warning, only `admin` kept
- `--purpose dsh,admin` → warning, `admin` removed, `dsh` kept

Output files:
- `/var/lib/mtls-gw/certs/<name>/cert.pem` — certificate
- `/var/lib/mtls-gw/certs/<name>/key.pem` — private key
- `/var/lib/mtls-gw/certs/<name>/device.p12` — for browser/mobile import (password printed by CLI)

---

## 4. Client Access

### 4.1 Browser (Windows/macOS)

Import the p12 (certmgr or `Import-PfxCertificate`), visit the gateway address, pick the device cert when prompted.

### 4.2 Mobile

- Android: Settings → Security → Install certificate → pick device.p12
- iOS: transfer p12 → install profile → trust

### 4.3 CLI tools

```bash
curl --cert cert.pem --key key.pem https://<gateway>:9443/
```

> Note: Windows schannel has a TLS 1.3 + client-cert compatibility issue (SEC_E_INTERNAL_ERROR).
> Browsers (BoringSSL) are unaffected; CLI tools should use TLS 1.2 or test with a browser.

---

## 5. Security Model

| Threat | Defense |
|--------|---------|
| Private key copied to another device | IP pre-check: cert SAN IP ≠ source IP → reject |
| Cert leaked / device lost | revoke single cert (DB status change, immediate) |
| Cert expiry | validity set at issue time (short for admin recommended) |
| Device cert attacks management plane | privilege separation: /admin/* admin-only |
| Unregistered cert | serial not in memory table → reject |
| DNS rebinding / CSRF (backend) | Host/Origin rewritten to loopback, fence passes naturally |

### Known Limitations

- **IP-bound network**: SAN binds the device IP; devices must use the bound network (e.g. tailnet) to pass the IP pre-check
- For multi-network access: add more IPs to the SAN, or use the TrustSource abstraction (below)

---

## 6. Future Work

### 6.1 TrustSource abstraction (planned)

IP pre-check currently binds to a specific network. Planned as a pluggable trust source:

```
TrustSource (interface) ── authorize(request) → {device identity} | deny
    ├─ IPBindSource   ← current: SAN IP binding
    ├─ LanSource      ← LAN IP whitelist
    └─ (future) other networks...
```

### 6.2 Web management panel (planned)

Both CLI and web panel are shells of the core process, both calling the core API (web does NOT call the CLI):

```
core daemon (mtls-gw) ── management API (controlled ops + audit)
    ├─ CLI (shell)
    └─ Web panel (shell, admin cert via mTLS)
```

### 6.3 More backends

Add one entry in `backends`:

```json
"backends": {
  "app-a": { "target": "http://127.0.0.1:3080", "listen": "0.0.0.0:9443" },
  "app-b": { "target": "http://127.0.0.1:8081", "listen": "0.0.0.0:9445" }
}
```

Then issue certs with `--purpose app-b`.

---

## 7. Unit Tests

```bash
go test ./...          # all tests
go test -v ./...       # verbose
go test -cover ./...   # coverage
```

| Package | Coverage | Tests |
|---------|----------|-------|
| `internal/db` | CRUD / revoke / overwrite / persistence reload | 3 |
| `internal/auth` | authorize / IP mismatch / unregistered / revoked / expired / IP-bind on-off | 8 |
| `internal/api` | issue / template fields / multi-purpose / admin rule / warnings | 10 |
| `internal/proxy` | routing / unknown purpose 404 / Host rewrite / Origin rewrite / WebSocket | 6 |

27 tests total. Coverage: db 83% / auth 72% / proxy 84% / api ~55%.

Test highlights:
- tests build a throwaway CA + server cert — no deployment env needed
- `TestAuthorizeIPMismatch` proves a copied private key is rejected (IP pre-check)
- `TestHostRewrite` / `TestOriginRewrite` prove header rewriting (the key to zero backend changes)
- `TestIssueCertAdminNotFirst` proves the admin-removal warning rule

---

## 8. Pitfalls (development notes)

1. **Go flag stops at first non-flag arg**: `--purpose admin` after a positional arg is not parsed → classify args manually
2. **No write access to /run root**: normal user cannot bind a Unix socket there → use systemd `RuntimeDirectory`
3. **Management API prefix**: use `/admin/` to avoid colliding with backend `/api/` RPC
4. **Origin must be rewritten too**: rewriting Host only → browser requests get 403
5. **Old process not restarted**: changed json tags don't take effect until daemon restart
