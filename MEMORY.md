# Project Memory - 3x-ui (vpn-ui)

## Meta
- Memory location: /home/mmd/work/vpn-ui/MEMORY.md
- Rule: Update this file after every significant step or discovery
- Last updated: 2026-02-20 (session 10)
- Branch: mmd (main branch: main)

## Project Identity
- **Name**: 3x-ui (fork/customization of MHSanaei/3x-ui)
- **Module**: `github.com/mhsanaei/3x-ui/v2`
- **Purpose**: Web management panel for Xray-core proxy/VPN server
- **Language**: Go 1.26 backend + Vue.js 2 frontend
- **Total Go LOC**: ~20,000 lines

## Architecture Overview

```
main.go                          Entry point (CLI + web server)
|
+-- config/config.go             Env-based configuration
+-- database/                    SQLite via GORM
|   +-- db.go                    Init, migrate, seed
|   +-- model/model.go           All DB models
+-- logger/logger.go             go-logging wrapper
+-- web/                         Main web application
|   +-- web.go                   Server init, Gin router, cron scheduler
|   +-- controller/              HTTP controllers (index, inbound, server, setting, xray_setting, api, websocket)
|   +-- service/                 Business logic (xray, inbound, setting, tgbot, user, server, l2tp, warp, outbound, panel, config)
|   +-- job/                     Background cron jobs (9 jobs)
|   +-- entity/entity.go         API request/response structs (Msg, AllSetting)
|   +-- global/                  Global state (web server ref, hash storage)
|   +-- session/session.go       Cookie-based session mgmt
|   +-- locale/locale.go         i18n with go-i18n + TOML files
|   +-- network/                 Auto-HTTPS listener/conn
|   +-- middleware/              Domain validator, redirect (/xui -> /panel)
|   +-- websocket/               Hub + notifier for real-time updates
|   +-- html/                    Go templates (pages, components, forms, modals)
|   +-- assets/                  Static assets (JS, CSS, fonts, vendor libs)
|   +-- translation/             13 language TOML files
+-- sub/                         Subscription server (separate HTTP server)
|   +-- sub.go                   Sub server lifecycle
|   +-- subController.go         Routes: /:subid (text), /:subid (JSON)
|   +-- subService.go            Link generation (vmess://, vless://, trojan://, ss://)
|   +-- subJsonService.go        JSON config generation for clients
|   +-- default.json             Default client Xray config template
+-- xray/                        Xray process management
|   +-- process.go               Start/stop binary, crash detection, uptime
|   +-- config.go                Config struct (mirrors Xray JSON)
|   +-- api.go                   gRPC client to Xray (traffic stats, user mgmt)
|   +-- log_writer.go            Log parsing, crash report writing
|   +-- traffic.go               Inbound/outbound traffic structs
|   +-- client_traffic.go        Per-client traffic model (DB table)
|   +-- inbound.go               InboundConfig struct
+-- util/                        Utilities
|   +-- common/                  Error helpers
|   +-- crypto/                  Bcrypt password hashing
|   +-- json_util/               RawMessage type
|   +-- random/                  Random string/number generators
|   +-- sys/                     Platform-specific (Linux/Win/macOS): TCP/UDP count, CPU%
|   +-- ldaputil/                LDAP client (FetchVlessFlags, AuthenticateUser)
```

## Key Technologies & Dependencies
| Component | Technology |
|-----------|-----------|
| Web framework | Gin (gin-gonic/gin) |
| Database | SQLite via GORM |
| Template engine | Go html/template (embedded FS in prod) |
| Frontend | Vue.js 2 + Ant Design Vue |
| HTTP client (FE) | Axios + QS |
| Session | gin-contrib/sessions (cookie store) |
| Cron | robfig/cron/v3 |
| Telegram bot | telego (mymmrac/telego) |
| Xray communication | gRPC (google.golang.org/grpc) |
| System metrics | gopsutil/v4 |
| LDAP | go-ldap/ldap/v3 |
| i18n | go-i18n/v2 + TOML |
| Compression | gin-contrib/gzip |
| WebSocket | gorilla/websocket |
| 2FA | xlzd/gotp + otpauth (JS) |
| QR codes | skip2/go-qrcode |
| Proxy core | xtls/xray-core |

## Database Models (SQLite)
| Table | Key Fields | Purpose |
|-------|-----------|---------|
| `users` | id, username, password(bcrypt) | Admin accounts |
| `inbounds` | id, user_id, up/down/total, remark, enable, expiry_time, protocol, settings(JSON), stream_settings(JSON), tag(unique), traffic_reset | Xray inbound configs |
| `client_traffics` | id, inbound_id, email(unique), up/down, total, expiry_time, enable, reset, last_online | Per-client traffic |
| `outbound_traffics` | id, tag(unique), up/down/total | Outbound traffic stats |
| `inbound_client_ips` | id, client_email(unique), ips(JSON) | IP tracking per client |
| `settings` | id, key, value | Key-value config store |
| `history_of_seeders` | id, seeder_name | Migration tracking |

## Supported Protocols
- **VLESS** (with XTLS Vision flow)
- **VMess** (UUID-based)
- **Trojan** (password-based)
- **Shadowsocks** (AES-128/256-GCM, ChaCha20, 2022 variants)
- **L2TP/IPsec** (first-class, paired with dokodemo-door)
- **PPTP** (first-class, PPP with MPPE)
- **OpenVPN** (first-class, dual UDP+TCP, RADIUS auth)
- **HTTP**, **SOCKS**, **Mixed**
- **WireGuard**, **TUN**, **Tunnel** (dokodemo-door)

## Transport/Stream Types
TCP, WebSocket, gRPC, HTTP/2, XHTTP, HTTPUpgrade, KCP

## Security Features
TLS, Reality, ECH certificates, ML-DSA-65, ML-KEM-768, X25519

## API Routes Summary
| Prefix | Controller | Key Endpoints |
|--------|-----------|--------------|
| `/` | IndexController | login, logout, getTwoFactorEnable |
| `/panel/` | XUIController | index, inbounds, settings, xray |
| `/panel/api/inbounds/` | InboundController | list, get, add, del, update, addClient, delClient, updateClient, clientIps, onlines, import, etc. (~20 endpoints) |
| `/panel/api/server/` | ServerController | status, cpuHistory, getXrayVersion, stop/restart, installXray, logs, getDb, importDB, getNewUUID, etc. (~18 endpoints) |
| `/panel/setting/` | SettingController | all, update, updateUser, restartPanel, defaultSettings |
| `/panel/xray/` | XraySettingController | getXraySetting, update, warp, testOutbound, outboundsTraffic |
| `/ws` | WebSocketController | WebSocket upgrade (real-time updates) |
| `/{subPath}/:subid` | SUBController | Subscription links (text + JSON) |

## Background Jobs (Cron)
| Job | Schedule | Purpose |
|-----|----------|---------|
| CheckXrayRunningJob | @every 1s | Restart Xray if crashed (requires 2 consecutive failures) |
| XrayTrafficJob | @every 10s | Collect traffic via gRPC, update DB, broadcast via WS |
| CheckClientIpJob | @every 10s | Parse access logs, enforce IP limits, disconnect excess |
| ClearLogsJob | @daily | Rotate and truncate log files |
| PeriodicTrafficResetJob | @daily/@weekly/@monthly | Reset traffic counters per schedule |
| StatsNotifyJob | Configurable | Send Telegram stats report |
| CheckCpuJob | @every 10s | Telegram alert if CPU > threshold |
| LdapSyncJob | Configurable | Sync clients from LDAP directory |
| CheckHashStorageJob | @every 2m | Clean expired Telegram callback hashes |

## Frontend Architecture
- **Framework**: Vue.js 2 with Ant Design Vue
- **Pages**: Login, Dashboard (index), Inbounds, Settings, Xray Config
- **Components**: Sidebar, ThemeSwitch, PersianDatepicker, ClientTable, etc.
- **API Communication**: Axios with URL-encoded POST, 401 redirect interceptor
- **Real-time**: WebSocket hub with topic-based broadcasting (status, traffic, inbounds, notifications, xray_state)
- **Theme**: Light/dark mode toggle
- **i18n**: 13 languages (EN, FA, ZH, RU, AR, ES, TR, etc.)
- **Date formats**: Gregorian + Jalalian (Persian) calendar

## Deployment
- **Setup script**: `setup-vpn-backend.sh` — installs all VPN backend deps (idempotent, Debian 12+/Ubuntu 22.04+)
- **Local compile**: Go 1.26 is available locally at `/usr/bin/go` — `CGO_ENABLED=1 go build -o x-ui main.go`
- **Server compile**: Also works on x-server at `/usr/local/go/bin/go`
- **Default port**: 2053 (panel), 2096 (subscription)
- **Data volume**: /etc/x-ui
- **Install script**: install.sh (shell-based installer, upstream)

## Configuration (Environment Variables)
| Variable | Default | Purpose |
|----------|---------|---------|
| XUI_LOG_LEVEL | info | Log level (debug/info/notice/warning/error) |
| XUI_DEBUG | false | Debug mode |
| XUI_BIN_FOLDER | bin | Xray binary folder |
| XUI_DB_FOLDER | /etc/x-ui | Database folder |
| XUI_ENABLE_FAIL2BAN | true | Enable fail2ban |

## Key Patterns & Conventions
- Services are zero-value structs with no constructor DI (just declare and use)
- Controllers register routes in `initRouter()` methods
- All API responses use `entity.Msg{Success, Msg, Obj}`
- Xray process is a mutex-protected singleton; config comparison avoids unnecessary restarts
- Client settings stored as JSON strings in inbound.Settings column
- Traffic collected via gRPC `QueryStats` with atomic reset
- L2TP inbounds skip Xray config, inject dokodemo-door pairs instead
- WebSocket uses worker pool (CPU*2, min 10, max 100) for broadcasting
- Password hashing: bcrypt (migrated from plaintext via seeder)
- Template functions include `i18n` for server-side translations
- Static assets embedded in binary for production, served from disk in dev

## Telegram Bot Features
- Admin commands: /status, /usage, /inbounds, /clients, /backup
- Client management: search, reset traffic, set expiry, set IP limit, enable/disable
- Add client flow with inline keyboards for traffic/expiry selection
- Login notifications (success/failure with IP)
- Periodic stats reports
- Database backup sending
- CPU threshold alerts
- Multi-admin support via chat IDs
- Hash storage for callback query state (auto-cleaned every 2min)
- Custom API server and proxy support

## Custom Additions (mmd branch)
- L2TP/IPsec as first-class inbound protocol
- PPTP as first-class inbound protocol
- OpenVPN as first-class inbound protocol (v2.8.13)
- Embedded RADIUS server for all VPN auth
- nftables-based traffic accounting
- Pre-built distro archive (vpn-ui-distro.tar.zst)
- Enhanced telego client robustness and retries
- Go 1.26 bump
- Version: 2.8.13

## Recent Bug Fixes & Improvements (2026-02-18)

### PPTP client deletion broken
- **Root cause**: `DelInboundClient()` in `web/service/inbound.go:750` used `client_key = "password"` for trojan/l2tp but missed pptp. Defaulted to `"id"`, so the lookup never matched and deletion silently failed.
- **Fix**: Added `|| oldInbound.Protocol == "pptp"` to the condition.

### PPTP dokodemo-door listen address
- **Root cause**: `GetDokodemoConfig()` in `web/service/pptp.go` had `Listen: "127.0.0.1"` while L2TP correctly used `"0.0.0.0"`. TPROXY-redirected traffic from PPP interfaces can't reach localhost.
- **Fix**: Changed to `"0.0.0.0"`.

### Wide cipher/encryption support (PPTP + L2TP)
- **PPTP PPP options** (`web/service/pptp.go` `GeneratePPPOptions`):
  - Removed `refuse-mschap` (allows MSCHAPv1 fallback for older clients)
  - Changed `require-mppe-128` → `require-mppe` (accepts 40/56/128-bit)
  - Removed `nobsdcomp`, `novj`, `novjccomp` (allows compression negotiation)
- **L2TP PPP options** (`web/service/l2tp.go` `GeneratePPPOptions`):
  - Added `refuse-pap`, `refuse-chap` (blocks plaintext auth)
  - Removed `debug` (noisy in production)
  - No MPPE required (IPsec provides encryption; MPPE breaks `noccp` clients like macOS)
  - Note: `lock` option is invalid for pppol2tp (kernel L2TP plugin), removed
- **L2TP IPsec ciphers** (`web/service/l2tp.go` `GenerateIPsecConfig`):
  - Removed `!` strict flag
  - IKE: AES256/128 × SHA256/SHA1 × modp2048/1024, plus 3DES-SHA1 (Windows 7, old Android)
  - ESP: AES256/128 × SHA256/SHA1, plus 3DES-SHA1

### Windows 10 L2TP connection stuck
- **Root cause**: `forceencaps=yes` was only set when `allowRaw=true`. Windows 10 (and most clients behind NAT) requires NAT-T (UDP/4500 encapsulation). Without it, server expects raw ESP which fails for NAT'd clients.
- **Fix**: Always use `forceencaps=yes` and `leftprotoport=17/%any` regardless of allowRaw.

### allowRaw=false not enforced (raw L2TP without PSK still worked)
- **Root cause**: xl2tpd listens on `0.0.0.0:1701` regardless of IPsec config. The `allowRaw` toggle only affected ipsec.conf `leftprotoport`/`forceencaps`, but didn't prevent direct UDP connections to xl2tpd.
- **Fix**: New `SetupRawL2tpFilter()` method in `web/service/l2tp.go`. When `allowRaw=false`, adds: `iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP`. The `-m policy --pol none` match drops packets that didn't arrive through IPsec. When `allowRaw=true`, rule is removed. Called from `GenerateAllConfigs()`.

### SoftEther/hwdsl2-aligned L2TP config (commit f5785464)
- **Context**: Windows 10 L2TP PSK still not connecting. Researched SoftEther VPN source and hwdsl2/setup-ipsec-vpn (most popular L2TP setup script). Applied their configuration patterns.
- **PPP options** now match hwdsl2 exactly:
  - `+mschap-v2` (additive, not `require-mschap-v2` which is exclusive)
  - `ipcp-accept-local` + `ipcp-accept-remote` (flexible IP negotiation)
  - `noccp` (disable CCP, avoids MPPE negotiation issues)
  - `connect-delay 5000` (5s delay for slow clients)
  - Removed `refuse-pap`, `refuse-chap` (xl2tpd handles via `require chap = yes`)
- **xl2tpd.conf**: Restored `require chap = yes` (matches hwdsl2), kept `flow bit = yes`
- **IPsec config** changes:
  - Added `keyexchange=ikev1` (explicit IKEv1)
  - Changed `leftprotoport=17/1701` (specific L2TP port, matches hwdsl2)
  - Increased `ikelifetime=24h`, `keylife=24h` (matches hwdsl2)
  - Use `sha2` shorthand in cipher proposals

### StrongSwan → Libreswan Migration: SOLVED Windows L2TP
- **Status**: SOLVED as of 2026-02-18 (session 6)
- **Root cause**: StrongSwan 6.x has a fundamental incompatibility with Windows 10/11 L2TP/IPsec in transport mode with NAT-T. IPsec SA establishes but Windows never sends L2TP packets through it (zero bytes on every SA). This is NOT a config issue — XFRM state is correct server-side.
- **Solution**: Replaced StrongSwan with **Libreswan 5.2** (same as hwdsl2 project uses)
- **Results**:
  - Windows 10 LTSC: WORKS (AES_CBC_256-HMAC_SHA1_96, confirmed traffic flow)
  - Windows 11: Fixed by removing `sha2-truncbug=yes` (truncates SHA2-256 to 96 bits, breaks Win11 which uses correct 128-bit)
  - iPhone/iOS: Added ECP DH groups (DH19/DH20) for IKE proposals
- **Code changes** (`web/service/l2tp.go`):
  - `GenerateIPsecConfig()` now writes `/etc/ipsec.conf` (Libreswan format) + `/etc/ipsec.secrets` (mode 0600)
  - Old swanctl config at `/etc/swanctl/conf.d/l2tp.conf` is cleaned up
  - `RestartServices()` just calls `ipsec restart` (no more `swanctl --load-all`)
- **Libreswan config format**:
  - `config setup`: `uniqueids=no`, `ikev1-policy=accept`, `logfile=/var/log/pluto.log`
  - `conn l2tp-psk`: `type=transport`, `authby=secret`, `pfs=no`, `rekey=no`, `keyexchange=ikev1`
  - IKE: `aes256-sha2;modp2048,...,aes256-sha2;dh20,aes256-sha2;dh19,...` (MODP2048 for Windows, ECP for iOS)
  - ESP: `aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,3des-sha1`
- **Key lessons**:
  - `sha2-truncbug=yes` breaks Windows 11 (uses correct 128-bit SHA2-256 truncation)
  - Libreswan 5.2 dropped `modp1024` support — use `modp2048` minimum
  - Libreswan 5.2 drops IKEv1 by default — must set `ikev1-policy=accept`
  - `dpdaction=clear` is obsolete in Libreswan 5.2
  - Server has both StrongSwan (disabled) and Libreswan installed — StrongSwan can be removed
- **Dependencies**: `apt-get install libreswan` (replaces strongswan for L2TP)

### Key patterns reinforced
- `DelInboundClient()` must use `password` as client_key for trojan/l2tp/pptp protocols (not `id`)
- TPROXY dokodemo-door must listen on `0.0.0.0` (not `127.0.0.1`) for TPROXY to work
- L2TP PPP options must NOT include `lock` (incompatible with pppol2tp kernel plugin)
- IPsec `forceencaps=yes` is required for Windows/NAT compatibility — always enable it
- xl2tpd `require chap = yes` works fine with PPP `+mschap-v2` (additive); it conflicted with `require-mschap-v2` (exclusive)
- pppd logs "Peer X authenticated with CHAP" even for MSCHAPv2 — generic log message
- Windows registry `AssumeUDPEncapsulationContextOnSendRule=2` needed for NAT-T L2TP
- **Controller vs Server service instances**: InboundController creates its own zero-value L2tpService/PptpService. `SetRadius()` is only called on Server's instances. Any method that needs `radiusSecret` must fall back to DB lookup (`SettingService.GetRadiusSecret()`) when in-memory field is empty. Fixed in session 9 (commit 94fbbf62).

## Embedded RADIUS Server (2026-02-18, session 7)
- **Architecture**: Replaced file-based auth (chap-secrets, usermap, ip-up/ip-down scripts, session files) with embedded Go RADIUS server
- **New file**: `web/service/radius.go` (~530 lines) — RadiusService
- **Library**: `layeh.com/radius` (v0.0.0-20231213012653-1006025d24f8)
- **Ports**: 127.0.0.1:1812 (auth), 127.0.0.1:1813 (acct)
- **Auth flow**: pppd → radius.so plugin → RADIUS Access-Request → Go queries SQLite → MS-CHAPv2 verify → Accept/Reject + MPPE keys
- **Acct flow**: pppd → RADIUS Acct-Start → Go creates session + nft counters; Acct-Stop → cleanup
- **Session tracking**: In-memory `map[string]*radiusSession` (key: Acct-Session-Id)
- **Traffic counting**: nft counters (unchanged 10s granularity), IP→email from RADIUS sessions
- **Disabled client**: RADIUS rejects auth, `KillSessionsByEmail()` kills active pppd processes
- **Panel restart**: Orphan sessions cleaned up on restart; interim-updates (60s) re-add sessions if PPP survives
- **Stale session cleanup**: `CleanStaleSessions()` runs every 60s, checks if PPP interface still exists

### Key implementation details
- **Dictionary fix (CRITICAL)**: pppd's `radius.so` has statically linked radiusclient that uses `INCLUDE` (no `$`) for sub-dictionaries, but `/etc/radcli/dictionary` uses `$INCLUDE`. Fix: generate self-contained dictionary at `/etc/ppp/radius/dictionary` with all standard + Microsoft VSA attributes inline.
- **PPP options changes**: `refuse-pap`, `refuse-chap`, `require-mschap-v2`, `plugin radius.so`, `radius-config-file /etc/ppp/radius/{proto}-{id}.conf`. Removed `auth` line (RADIUS handles it).
- **xl2tpd.conf**: Removed `require chap = yes` and `refuse pap = yes` (pppd options now enforce auth type)
- **RADIUS client config**: Per-inbound at `/etc/ppp/radius/{proto}-{id}.conf`, shared `/etc/ppp/radius/servers`
- **NAS-Identifier**: `l2tp-{id}` or `pptp-{id}` — identifies protocol + inbound for auth handler
- **MS-CHAPv2**: `rfc2759.GenerateNTResponse()` for verification, `rfc3079.MakeKey()` for MPPE keys
- **RADIUS secret**: Random 32-char hex, stored in settings DB (`GetRadiusSecret`/`SetRadiusSecret`)
- **Acct-Interim-Interval**: 60s (minimum pppd allows), sent in Access-Accept

### Files removed/modified
- **Removed**: `GenerateChapSecrets()`, `GenerateUserMap()`, `GenerateIpUpDown()`, `readSessions()`, `readSessionList()`, session/usermap file constants — from both l2tp.go and pptp.go
- **Modified**: `nftables.go` — added `AddClientAccounting()`/`RemoveClientAccounting()`, `CollectAndResetTraffic()` now takes session maps instead of reading files
- **Modified**: `web.go` — starts RADIUS server, generates secret, passes to L2TP/PPTP services
- **Modified**: `xray_traffic_job.go` — gets session maps from RadiusService, passes to NftService
- **Modified**: `setting.go` — added `GetRadiusSecret`/`SetRadiusSecret`
- **Added dependency**: `go.mod` — `layeh.com/radius`

### Tested on sandbox
- L2TP: auth accepted, acct-start/stop/interim, traffic counters, disable → reject ✅
- PPTP: auth accepted, MPPE encryption, acct-start/stop, traffic counters, disable → reject ✅
- Both protocols simultaneously ✅
- Orphan session cleanup on panel restart ✅
- No stale files (chap-secrets, usermap, ip-up/ip-down all eliminated) ✅

## OpenVPN Protocol Support (v2.8.13, session 8)
- **Architecture**: First-class inbound protocol, RADIUS auth (PAP), nftables accounting, management socket kill
- **New file**: `web/service/openvpn.go` (~700 lines) — OpenVpnService
- **Subnets**: UDP `10.2.{id}.0/24`, TCP `10.3.{id}.0/24`
- **Dual protocol**: Each inbound runs 2 OpenVPN instances (UDP on `inbound.Port`, TCP on `settings.tcpPort`)
- **Systemd**: `openvpn-server@server-{id}-udp` and `openvpn-server@server-{id}-tcp`
- **Configs**: `/etc/openvpn/server/server-{id}-{udp|tcp}.conf`, certs at `/etc/openvpn/server-{id}/`
- **Status files**: `/run/openvpn/status-{id}-{udp|tcp}.log`, mgmt sockets at `/run/openvpn/mgmt-{id}-{udp|tcp}.sock`
- **Auth**: `auth-user-pass-verify "/usr/local/x-ui/x-ui openvpn-auth {id}" via-file` → PAP to RADIUS
- **Sessions**: `client-connect` / `client-disconnect` scripts → RADIUS Acct-Start/Stop via x-ui subcommands
- **Traffic routing**: Direct NAT (MASQUERADE), no Xray/TPROXY — nftables `nat_post` chain
- **Disable**: Kill via management unix socket (`kill {username}`)
- **Certs**: Panel-generated self-signed CA (ECDSA P-384), server cert, tls-crypt key
- **Client config**: `.ovpn` download via `GET /panel/api/inbounds/:id/ovpn/{udp|tcp}`
- **Cert generation**: `POST /panel/api/inbounds/:id/generate-openvpn-certs`

### Files changed for OpenVPN
- `web/service/openvpn.go` (NEW, ~700 lines)
- `web/html/form/protocol/openvpn.html` (NEW, ~120 lines)
- `main.go` — 3 subcommands: `openvpn-auth`, `openvpn-connect`, `openvpn-disconnect`
- `database/model/model.go` — `OPENVPN Protocol = "openvpn"`
- `web/service/radius.go` — PAP support, `"openvpn"` in `parseNASIdentifier()`, `isIPActive()` protocol-aware
- `web/service/nftables.go` — `openvpn_acct` chain, NAT MASQUERADE, 3rd param in `CollectAndResetTraffic()`
- `web/service/inbound.go` — `"openvpn"` in client_key/disable/username checks
- `web/controller/inbound.go` — `onOpenVpnChanged()`, cert/config download routes
- `web/job/xray_traffic_job.go` — OpenVPN traffic collection, `RadiusService` pointer
- `web/web.go` — `InitOpenVpn()` on startup
- `web/assets/js/model/inbound.js` — `OpenVpnSettings`, `OpenVpnUser` classes
- `web/html/form/inbound.html` — protocol form include
- `web/html/form/client.html` — OPENVPN in v-if conditions
- `web/html/modals/client_modal.html` + `client_bulk_modal.html` — OPENVPN cases
- `config/version` — bumped to 2.8.13

### Bugs fixed during OpenVPN testing
- **`radius.Exchange(nil, ...)` panic**: Go RADIUS library requires non-nil context. Fixed: `context.Background()`.
- **Traffic job blocked by Xray**: `IsXrayRunning()` early return blocked ALL traffic collection. Restructured to collect VPN traffic independently.
- **Stale session cleanup removing OpenVPN**: `isIPActive()` checked `ip addr show` — OpenVPN client IPs not on interfaces (routed through tun). Fixed: route check (`ip route get`) for OpenVPN.
- **RadiusService instance mismatch**: Traffic job had zero-value struct, separate from RADIUS server instance. Fixed: changed to `*service.RadiusService` pointer.
- **OpenVPN `dh none` missing**: OpenVPN 2.6 requires explicit `dh none` with ECDSA certs.

### Key patterns learned
- OpenVPN client IPs are NOT on server interfaces — only routed through tun device
- `RadiusService` is stateful (sessions map) — must pass as pointer, not value type
- OpenVPN `redirect-gateway def1` causes SSH loss to VPN client — access via tunnel IP from server
- OpenVPN systemd has `PrivateTmp=true` — temp files are namespaced
- Gin `Recovery()` with `DefaultErrorWriter=io.Discard` silently swallows panics → empty 500 response
- `layeh.com/radius` `Exchange()` requires non-nil `context.Context`
- OpenVPN `verify-client-cert none` + `username-as-common-name` = username/password only auth

### Tested on sandbox
- OpenVPN UDP client connection from x-client ✅
- RADIUS PAP auth (accept + reject) ✅
- nft counter creation on connect, removal on disconnect ✅
- Traffic collection pipeline (nft → RADIUS sessions → DB) ✅
- Disable client → kill via management socket → RADIUS reject reconnect ✅
- NAT masquerade (client traffic routed through server IP) ✅
- OpenVPN packages: `openvpn` on x-server, `openvpn` on x-client

## Per-User Email Routing for L2TP/PPTP (2026-02-20, session 9, commit c2138b43)
- **Problem**: Xray's `user` routing field doesn't work with dokodemo-door (no per-user identification). L2TP/PPTP could only be routed by `inboundTag`, not per-user.
- **Solution**: Two-part approach — deterministic IP assignment + transparent routing rule translation.

### Deterministic IP assignment (radius.go)
- RADIUS Access-Accept now includes `Framed-IP-Address` based on client's index in the inbound's client list
- Index 0 → startIP, index 1 → startIP+1, etc. (e.g., `10.0.2.10`, `10.0.2.11`, ...)
- Functions: `getClientIP()` (on RadiusService), `computeVpnClientIP()`, `vpnSubnet()`
- `BuildVpnEmailToIPMap()` — exported, builds email→IP map for all enabled L2TP/PPTP clients

### Routing rule translation (xray.go)
- `translateVpnRoutingRules()` called at end of `GetXrayConfig()`
- Scans all routing rules for `user` field, checks emails against VPN client map
- VPN emails → creates `source`-based rule (copy all fields except `user`, add `source` IPs)
- Non-VPN emails → kept as original `user` rule
- Mixed rules (some VPN, some Xray) → split into two rules (source + user)
- **Transparent to UI**: operators write `user: ["email"]` same as VMess/VLESS/Trojan

### Key detail
- TPROXY preserves source IPs, so Xray sees each user's unique PPP IP in dokodemo-door traffic
- No UI changes needed — panel template routing rules "just work" with VPN emails

### Tested on sandbox
- L2TP user "a" (index 1) → IP `10.0.2.11` (correct: startIP 10.0.2.10 + 1) ✅
- Template `{"user": ["a"], "outboundTag": "SVXNL@SVXNL"}` → generated `{"source": ["10.0.2.11"], "outboundTag": "SVXNL@SVXNL"}` ✅
- Multiple rules with same email correctly translated independently ✅

## nftables (2026-02-18, session 5)
- **Architecture**: Single `table ip vpn` with 5 chains: prerouting (TPROXY + jumps), postrouting (jumps), input (raw L2TP filter), l2tp_acct (dynamic per-client), pptp_acct (dynamic per-client)
- **Key design**: Static chains flushed+rebuilt on config regen. Accounting chains NEVER flushed — dynamic per-client rules managed by RADIUS acct events (was ip-up/ip-down scripts, now `AddClientAccounting`/`RemoveClientAccounting`).
- **Named counters**: `l2tp_up_10_0_2_10`, `l2tp_down_10_0_2_10`, etc. Created/deleted by RADIUS acct.
- **Traffic collection**: `nft -j reset counters table ip vpn` — atomic read+reset, JSON output.
- **Config file**: `/etc/x-ui/vpn.nft` — loaded atomically with `nft -f`
- **IPsec filter**: `meta secpath exists` (replaces `-m policy --dir in --pol none`)
- **Modprobe**: `nf_tproxy_ipv4` (not `xt_TPROXY`)
