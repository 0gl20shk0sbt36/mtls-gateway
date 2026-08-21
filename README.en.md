# mtls-gw — Generic mTLS Gateway

A **generic access gateway** built on mTLS client certificates: device-level authentication + role-based routing. Not tied to any specific application — reuse it for any self-hosted service.

## Architecture in One Line

**Certificate = identity, SQLite = authorization.** Every request passes two gates: ① TLS chain verification (CA-signed) ② database registration (serial present + not revoked + not expired). **Memory is authoritative**: the full DB is loaded into a map at startup, request verification reads memory only (zero I/O), and mutations write through to the DB.

```
client (holds device cert) ──mTLS──▶ mtls-gw ──▶ backend service
                                     │
                                     ├─ /info port: service discovery (any registered cert)
                                     ├─ admin port: issue/revoke/config (admin_role cert only)
                                     └─ business port: mappings routing + services role authz
```

---

## 1. Core Design

### 1.1 Certificate = Identity, DB = Authorization (separation of concerns)

- The certificate contains **no purpose/permission fields**; authorization lives entirely in SQLite. Revoke or change permissions by editing the DB — no re-issuing.
- The cert SAN is bound to the device IP (TS IP); copying the private key to another device is rejected on IP mismatch (`require_ip_bind=true`).
- One cert can hold **multiple roles** (`roles` list); one role can access multiple services.

### 1.2 Mapping & Authorization Model (two tables)

**mappings (channels)** = the unique routing entity, deduplicated by `listen`:

```toml
[[mappings]]
id = "dsh-main"                    # mnemonic (referenced by services)
listen = ":9443"                   # entry :port[/path]
target = "http://127.0.0.1:3080"   # backend URL (URL path = prefix rewrite, nginx proxy_pass semantics)
```

**services** = every service must be declared; authorization by role intersection:

```toml
[[services]]
name = "dsh"
channels = ["dsh-main"]            # this service's channels (mapping ids)
roles = ["dsh"]                    # roles allowed; "any" = any registered cert
```

Authorization rule: after a request hits a mapping, it is allowed only if the cert's `roles` intersect the union of `roles` of all services referencing that mapping (or contain `any`); otherwise 403.

### 1.3 Routing & Forwarding

- Same-port multi-path uses **longest-prefix matching**; no path = whole-port fallback.
- Prefix rewrite: strip the `listen` path prefix, replace with the `target` path prefix.
- **Host/Origin auto-rewritten** to the backend loopback address — no need to touch the backend's trust fence.
- WebSocket pass-through (Hijacker).
- Request path normalized before matching (strips `..`/`.` dot-segments + backslashes, prevents path traversal).

### 1.4 Verification Flow (per request)

1. mTLS handshake (TLS 1.2+, client cert chain verified against CA)
2. IP pre-check (cert SAN IP == source IP, when `require_ip_bind=true`)
3. serial lookup in the in-memory table (present + `enabled` + not expired)
4. mapping match + role authorization
5. reverse-proxy forward

### 1.5 Dual Management Channel

| Channel | Access | Permission |
|---|---|---|
| Unix socket (local CLI) | file perms 600 | direct admin (Linux only) |
| TCP admin API | mTLS cert | `admin_role` cert only |

The CLI and Web panel are **peer shells** of the management API; the Web panel never calls the CLI directly.

---

## 2. Quick Start

### 2.1 Build

```bash
go build ./cmd/mtls-gw ./cmd/mtls-gw-cli ./cmd/mtls-relay
```

### 2.2 Configure

```bash
cp config.example.toml /etc/mtls-gw/config.toml
# edit: fill CA/cert paths, mappings, services
```

Full field reference in [config.example.toml](./config.example.toml). Core fields:

| Field | Meaning |
|---|---|
| `bind_host` | bind address for all listeners (business/admin/discovery) |
| `ca` / `ca_key` | CA cert/key (for issuing; key 600) |
| `server_cert` / `server_key` | gateway's own TLS cert |
| `admin_role` | built-in admin role name (default `mtls-superadmin`; avoid common names) |
| `admin_listen` | admin API port (admin_role cert only) |
| `info_listen` | `/info` discovery port (any registered cert) |
| `config_mode` | `mutable` (persist, default) / `ephemeral` (memory only) / `immutable` (read-only) |
| `lang` | error message language `zh` / `en` (default zh) |
| `key_type` / `key_bits` | issued key: rsa 2048/3072/4096 or ecdsa 256/384/521 |
| `default_days` / `admin_days` | default validity for regular/admin certs |

### 2.3 Run

```bash
/usr/local/bin/mtls-gw -config /etc/mtls-gw/config.toml
```

### 2.4 Issue a cert (local CLI, Unix socket)

```bash
mtls-gw-cli -sock /run/mtls-gw/mtls-gw.sock issue \
  -name dev-laptop -purpose dsh -ts-ip 100.64.0.10
mtls-gw-cli revoke -serial <serial>
mtls-gw-cli list
```

> Windows has no Unix socket; issue via the TCP admin API (requires an admin cert).

---

## 3. Client Integration

### 3.1 Client relay (mtls-relay)

Client devices run the relay daemon: `/info` discovery → per-service local tunnels → WebUI management.

```bash
mtls-relay -config ~/.mtls-relay/relay.json
# or via WebUI: pick cert → verify → add service tunnel
```

relay config (`relay.json`):

```json
{
  "server_addr": "gw.example:9499",
  "admin_addr": "gw.example:9444",
  "server_ca": "/path/to/ca.crt",
  "listen_host": "127.0.0.1",
  "cert": {"source": "dir", "arg": "/path/to/certs"},
  "tunnels": [
    {"service": "dsh", "cert_id": "dev-laptop", "routes": [{"channel": ":9443", "local": ":9443"}]}
  ]
}
```

- `server_addr` = `/info` discovery endpoint; `admin_addr` = admin endpoint (cert management, separate)
- Tunnels are built **per service** (one service = multiple channels); local routes can override port/path
- Cert rotation / server address changes rebuild tunnels automatically

### 3.2 WebUI

The relay ships a WebUI (`--listen-admin :28083`):

- **Run control + tunnel table** (grouped by service, status/traffic)
- **Cert picker** (after selecting, `/info` discovers that cert's accessible services)
- **Add tunnel** (pick service → local routes auto-filled)
- **Cert management console** (locked by default: pick admin cert → unlock with password → issue/revoke via admin_addr)

### 3.3 Browser / Phone

Import the p12 (private key + password) into the browser/phone — no extra software needed.

---

## 4. Security Model

- **Mutual mTLS**: client verifies the gateway CA; gateway verifies the client CA chain
- **Cert SAN binds IP**: copied private keys rejected on IP mismatch
- **Least-privilege roles**: cert roles intersect service roles; admin_role certs can only reach the admin API, never business services
- **Management-plane isolation**: business/admin/discovery on separate ports; admin API independent of business ports
- **DNS-rebinding protection**: relay admin API enforces loopback + Origin validation
- **server_ca unavailable → refuse startup**: prevents MITM via downgrade to system roots
- **Duplicate cert names forbidden**: pre-issue dedup (incl. revoked), prevents same-name confusion
- **Error redaction**: auth failures return only `forbidden`; details go to the event log only
- **Timeout/size limits**: ReadTimeout/WriteTimeout/IdleTimeout on all ports + MaxBytesReader 4MB

### Known Limitations

- Windows has no Unix socket; CLI issuing goes through the TCP admin API
- Cert expiry compared as `yyyy-mm-dd` strings (still valid on the expiry day)
- Newly issued certs need a gateway reload/restart before `/info` sees them

---

## 5. Tests

```bash
go test -race ./...          # Go unit/integration (178 test functions, -race green)
go vet ./...
gofmt -l cmd internal        # must be empty (enforced by CI)

# frontend
node --test internal/relayweb/web/test/*.test.js   # 8 unit tests
# E2E (run setup.sh first to build the environment)
bash internal/relayweb/web/e2e/setup.sh /tmp/mtls-e2e
node --test internal/relayweb/web/e2e/*.test.mjs   # 14 tests
```

- Tests build a **temporary CA + server cert** in-test, no deployment dependency.
- CI (GitHub Actions): build + vet + gofmt + test + race on Go 1.25 + 1.26; tagged releases auto-cross-compile.

---

## 6. Project Layout

| Directory | Responsibility |
|---|---|
| `cmd/mtls-gw` | server daemon (config parse + multi-port mTLS + admin API) |
| `cmd/mtls-gw-cli` | local management CLI (Unix socket) |
| `cmd/mtls-relay` | client relay daemon (/info discovery → tunnels + WebUI) |
| `internal/db` | SQLite persistence + in-memory authoritative table |
| `internal/auth` | authorization (IP pre-check + SAN + serial lookup + roles) |
| `internal/proxy` | reverse proxy (mapping routing + prefix rewrite + Host/Origin rewrite) |
| `internal/api` | management API (issue/revoke/list + p12) |
| `internal/relay` | client core (cert source / tunnels / admin bridge) |
| `internal/relayweb` | client WebUI (go:embed) |
| `internal/i18n` | zh/en error message tables |
| `internal/pathutil` | path utilities (dot-segment cleanup) |

## 7. Audit History

Full audit changelog in [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md) (31 pro batches × 3 tracks + 2 flash sweeps; 30+ real bugs + 25+ security hardening). Unfinished items in [TODO.md](./TODO.md).
