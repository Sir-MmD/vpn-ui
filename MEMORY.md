# Project Memory - 3x-ui (vpn-ui)

## Meta
- Memory location: /home/mmd/work/vpn-ui/MEMORY.md
- Rule: Update this file after every significant step or discovery
- Last updated: 2026-02-18
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
- **Docker**: Multi-stage build (Go 1.26 alpine builder -> alpine runtime)
- **Systemd**: Service files for Debian, RHEL, Arch
- **Default port**: 2053 (panel), 2096 (subscription)
- **Data volume**: /etc/x-ui
- **Fail2Ban**: Configured in Docker (SSH disabled)
- **Install script**: install.sh (shell-based installer)

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
- L2TP traffic/expiry limit enforcement (DisableClients, chap-secrets regen, PPP session kill)
- L2TP client JS model: `_totalGB`/`_expiryTime` getters/setters, `limitIp` (was `ipLimit`), `reset`/`created_at`/`updated_at` fields
- L2TP unique username enforcement (AddInbound, AddInboundClient, UpdateInboundClient)
- L2TP client count in Inbounds section (added Protocols.L2TP to setInbounds)
- L2TP Allow Raw mode: `allowRaw` toggle in IPsec settings, uses forceencaps+NAT-T so raw L2TP and PSK can coexist
- Pre-built distro archive (vpn-ui-distro.tar.zst)
- Enhanced telego client robustness and retries
- Timeouts and delays for backup sends
- Go 1.26 bump
- Version: 2.8.12

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

## L2TP Enforcement Architecture
- Traffic/expiry limits detected by `disableInvalidClients()` in inbound.go (same SQL for all protocols)
- For L2TP clients: `disableInvalidClients` returns their emails separately (skips useless `RemoveUser` call)
- `AddTraffic` propagates L2TP disabled emails to caller
- `XrayTrafficJob.Run()` calls `l2tpService.DisableClients(emails)` which:
  1. Kills active PPP sessions (via /var/run/pppX.pid)
  2. Regenerates chap-secrets (excludes disabled clients via `getDisabledEmails()` DB check)
  3. Regenerates usermap (same exclusion)
- `GenerateChapSecrets` and `GenerateUserMap` cross-check `client_traffics.enable` (not just JSON `Enable`)
- Controller reset methods (`resetClientTraffic`, `resetAllTraffics`, `resetAllClientTraffics`) call `onL2tpChanged()` to re-add users after reset

## nftables Migration (2026-02-18, session 5)
- **Migrated**: L2TP/PPTP from ~20 iptables commands to native nftables (`table ip vpn`)
- **New file**: `web/service/nftables.go` — NftService with ApplyNftRules(), CollectAndResetTraffic(), CleanupLegacyIptables()
- **Architecture**: Single `table ip vpn` with 5 chains: prerouting (TPROXY + jumps), postrouting (jumps), input (raw L2TP filter), l2tp_acct (dynamic per-client), pptp_acct (dynamic per-client)
- **Key design**: Static chains (prerouting/postrouting/input) are flushed+rebuilt on config regen. Accounting chains (l2tp_acct/pptp_acct) are NEVER flushed — their dynamic per-client rules (added by ip-up.d) survive.
- **Named counters**: `l2tp_up_10_0_2_10`, `l2tp_down_10_0_2_10`, etc. Created by ip-up.d, deleted by ip-down.d.
- **Traffic collection**: `nft -j reset counters table ip vpn` — atomic read+reset, JSON output. Replaces fragile iptables text parsing and the race-prone separate -L/-Z calls.
- **Config file**: `/etc/x-ui/vpn.nft` — loaded atomically with `nft -f`
- **IPsec filter**: `meta secpath exists` in nft (replaces `-m policy --dir in --pol none`)
- **ip-up/ip-down scripts**: Each protocol's script exits early if username not in its usermap (prevents cross-protocol spurious counters)
- **Removed from l2tp.go**: SetupRawL2tpFilter, SetupTproxy, CleanupTproxy, SetupAcctChain, CollectL2tpTraffic, l2tpAcctChain constant
- **Removed from pptp.go**: SetupTproxy, CleanupTproxy, SetupAcctChain, CollectPptpTraffic, pptpAcctChain constant
- **Removed from inbound.go**: CleanupTproxy calls in delInbound (nft regen handles it)
- **xray_traffic_job.go**: Single `nftService.CollectAndResetTraffic()` replaces two separate collection calls
- **Modprobe change**: `xt_TPROXY` → `nf_tproxy_ipv4` (nftables kernel module)
- **Tested**: L2TP and PPTP connections, traffic counting, counter reset, disconnect cleanup, legacy iptables cleanup — all verified on x-server
