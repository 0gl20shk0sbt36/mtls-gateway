# mtls-gw — Generic mTLS Gateway

A **generic access gateway** built on mTLS client certificates: device-level authentication + role-based routing. Not tied to any specific application — reuse it for any self-hosted service.

> **Project origin**: built initially for **DSH (DeepSeek Harness, DeepSeek's AI agent framework)** — its Web UI listens on loopback only, so no other device could reach it;
> this project is essentially an "**mTLS-encrypted equivalent of an SSH tunnel**": client certificates provide device-level authentication to safely expose loopback-only services to other devices.
> It was then generalized into a generic mTLS gateway — wiring up any HTTP service only requires adding a `mappings` channel + a `services` declaration + issuing a cert with the matching `roles`.

## Architecture in One Line

**Certificate = identity, SQLite = authorization.** Every request passes two gates: ① TLS chain verification (CA-signed) ② database registration (serial present + not revoked + not expired). **Memory is authoritative**: the full DB is loaded into a map at startup, request verification reads memory only (zero I/O), and mutations write through to the DB.

```
client (holds device cert) ──mTLS──▶ mtls-gw ──▶ backend service
                                      │
                                      ├─ /info port: service discovery (any registered cert)
                                      ├─ /admin/reload: full hot reload (admin_role cert only, called by mtls-admin)
                                      └─ business port: mappings routing + services role authz

mtls-admin (separate process): admin port issue/revoke/config (admin_role cert only) + Unix socket (local CLI)
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

### 1.5 Dual Management Channel (separate process mtls-admin)

Management runs in a **separate process mtls-admin** (reads the same config.toml as mtls-gw):
the gateway is a pure data plane (auth + routing + forwarding), the admin process is the sole
writer (DB/config); after any change it calls the gateway's `POST /admin/reload` for a full hot
reload (the gateway's in-memory copy is read-only and atomically swapped).

| Channel | Access | Permission |
|---|---|---|
| Unix socket (local CLI) | file perms 600 | direct admin (Linux only) |
| TCP admin API | mTLS cert | `admin_role` cert only |

The CLI and Web panel are **peer shells** of the management API; the Web panel never calls the CLI directly. Both connect to mtls-admin.

### 1.6 Glossary (quick reference)

| Term | Meaning |
|---|---|
| **mTLS gateway** | The server side as a whole: device-level cert authentication + role-based routing, not tied to any specific app |
| **mtls-gw / mtls-admin** | Server-side **two processes**: gateway = pure data plane (auth + routing + forwarding); admin process = sole writer (issue/revoke/change config). Both read the same config.toml and ignore irrelevant fields |
| **Cert = identity, SQLite = permissions** | Certs only prove who you are (CA-signed + SAN-bound IP); permissions (roles) live entirely in the DB; changing roles/revoking never requires re-issuing |
| **roles vs purposes** | **Two names for the same concept**: config calls it `roles` (service declarations / issue validation), the DB column calls it `purposes` (the cert's role list). Same role system, not two things |
| **role** | Role name `[A-Za-z0-9_-]+`; service roles and issued purposes must both be declared in the config `roles` list |
| **`any` role** | Writing `any` in a service declaration = any **registered** cert may access (still passes mTLS + registration checks); forbidden as a declared role or issued to a cert |
| **`null` route** | Writing `null` in a service's roles = **anonymous access** (no cert required, anyone can reach it); the deployer owns the port exposure |
| **`admin_role`** | Built-in admin role (default `mtls-superadmin`): a cert holding it gets management rights; forbidden in service roles / the roles declaration list (privilege-escalation guard) |
| **TS IP** | The device IP written into the cert SAN (`--ts-ip`; typically a Tailscale 100.x address); with `require_ip_bind=true` the source IP must match, preventing private-key copying to other devices |
| **mapping / service** | Channel (the only routing entity, uniqueness by `listen`) / service declaration (`channels` reference mapping ids + `roles` for authorization); access = cert roles intersect the union of roles of all services referencing that mapping |
| **whole-port vs path routing** | `listen` without a path = whole-port fallback (client relay uses TCP passthrough); with a path = prefix matching (HTTP reverse proxy, nginx proxy_pass semantics); multiple path routes share one listener |
| **relay (client)** | **relay is a client**: it actively dials out to the gateway (server) with a device cert and maps gateway services to local ports. Topology is "client → gateway" — don't misread the package name `relay` as a server |
| **`/info` discovery** | Anonymous gateway endpoint: no cert → returns the CA (clients filter their cert sources); with a cert → returns the services that cert may access; relay only needs one `server_addr` |
| **config_mode (3 states)** | `mutable` (persist + backup, default) / `ephemeral` (memory only, testing/temporary) / `immutable` (read-only, config CRUD rejected); changes require restarting both processes |
| **X-Auth-Purpose** | Internal **trusted header** for the admin API: set by mtls-admin only after outer mTLS auth + admin_role checks pass; the inner layer trusts it — client forgery is blocked by the outer layer first |
| **Standalone gateway** | mtls-gw does not depend on mtls-admin: a minimal config (data-plane fields only) starts and serves fully (auth/routing/forwarding/logs); it just cannot issue certs or change config online (pair with `immutable`) |

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
| `info_listen` | `/info` discovery port (any registered cert) |
| `reload_listen` | gateway `/admin/reload` port (called by mtls-admin, admin_role cert only; empty = merged with info port) |
| `admin_listen` | admin API port (admin_role cert only; owned by the mtls-admin process) |
| `config_mode` | `mutable` (persist, default) / `ephemeral` (memory only) / `immutable` (read-only) |
| `lang` | error message language `zh` / `en` (default zh) |
| `key_type` / `key_bits` | issued key: rsa 2048/3072/4096 or ecdsa 256/384/521 |
| `default_days` / `admin_days` | default validity for regular/admin certs |

### 2.3 Run (two processes)

```bash
/usr/local/bin/mtls-gw   -config /etc/mtls-gw/config.toml   # gateway (pure data plane)
/usr/local/bin/mtls-admin -config /etc/mtls-gw/config.toml  # admin process (issue/revoke/config)
```

### 2.4 Issue a cert (local CLI, connecting to mtls-admin's Unix socket)

```bash
mtls-gw-cli -sock /run/mtls-gw/mtls-gw.sock issue \
  -name dev-laptop -purpose dsh -ts-ip 100.64.0.10
mtls-gw-cli revoke -serial <serial>
mtls-gw-cli list
```

> The Unix socket is served by mtls-admin (same config as the gateway, same `sock_path`).
> Windows has no Unix socket; issue via the TCP admin API (requires an admin cert; `admin_addr` points at mtls-admin).

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
  "cert_dir": "/path/to/certs",
  "tunnels": [
    {"service": "dsh", "cert_id": "dev-laptop", "routes": [{"channel": ":9443", "local": ":9443"}]}
  ]
}
```

- `server_addr` = `/info` discovery endpoint; `admin_addr` = admin endpoint (cert management, separate)
- `cert_dir` = client cert source: empty = system cert store (platform-native identity store: Windows "Personal/My" CNG / Linux convention dir `~/.mtls-gw/certs` / Android app-private dir), non-empty = dir source (one cert per subdirectory); config wins over the `-source`/`-source-arg` startup flags
- `log_file` = runtime log path (tunnel/cert/connection events, **terminal + file double-write**; empty = platform default: Windows exe-dir/`mtls-relay` component subdir / Linux `~/.cache/mtls-relay`)
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
- **Startup permission pre-check (Linux)**: checks every file/dir referenced by config (CA/DB/certs/logs/sock/persist dirs) before starting; insufficient permissions → refuse startup with output on stderr (and best-effort write to the event log) — prevents "running sick with an unwritable dir" causing lost persistence / memory-disk divergence. Key files additionally require `mode&0o007==0` (no world read/write); **0640 (group-readable) is allowed** — trade-off: common in single-user/trusted-group deployments; tighten to 0600 if you need owner-only
- **Duplicate cert names forbidden**: pre-issue dedup (incl. revoked), prevents same-name confusion
- **Error redaction**: auth failures return only `forbidden`; details go to the event log only
- **Timeout/size limits**: ReadTimeout/WriteTimeout/IdleTimeout on all ports + MaxBytesReader 4MB

### Known Limitations

- Windows has no Unix socket; CLI issuing goes through the TCP admin API
- Cert expiry compared as `yyyy-mm-dd` strings (still valid on the expiry day)
- Without `gateway_reload_addr` configured, newly issued certs need a manual gateway `/admin/reload` (or restart) before `/info` sees them; with it configured, mtls-admin auto-reloads the gateway after every issue/revoke

---

## 5. Tests

```bash
go test -race ./...          # Go unit/integration (235 test functions, -race green)
go vet ./...
gofmt -l cmd internal        # must be empty (enforced by CI)

# frontend
node --test internal/relayweb/web/test/*.test.js   # 8 unit tests
# E2E (run setup.sh first to build the environment)
bash internal/relayweb/web/e2e/setup.sh /tmp/mtls-e2e
node --test internal/relayweb/web/e2e/*.test.mjs   # 15 tests
```

- Tests build a **temporary CA + server cert** in-test, no deployment dependency.
- CI (GitHub Actions): dual Go versions (1.25/1.26) build+vet+gofmt+test+race / WebUI unit / playwright E2E / Windows real-machine tests / Windows+Android cross-compile; tagged releases auto-cross-compile to multiple platforms.

---

## 6. Project Layout

| Directory | Responsibility |
|---|---|
| `cmd/mtls-gw` | gateway daemon (pure data plane: auth + routing + forwarding + /info + reload) |
| `cmd/mtls-admin` | separate admin process (issue/revoke/config CRUD, reads the same config; calls the gateway reload after changes) |
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

Full audit changelog in [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md) (31 pro batches × 3 tracks + 2 flash sweeps + 2026-08-22 three-round subagent review iterations + CI first-run fixes; 30+ real bugs + 25+ security hardening). Unfinished items in [TODO.md](./TODO.md).
