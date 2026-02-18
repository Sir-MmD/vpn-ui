# VPN-UI (3x-ui + L2TP/IPsec + PPTP + OpenVPN)

A fork of [3x-ui](https://github.com/MHSanaei/3x-ui) that adds **L2TP/IPsec**, **PPTP**, and **OpenVPN** as first-class inbound protocols alongside the existing Xray protocols (VMess, VLESS, Trojan, Shadowsocks, etc.).

All VPN clients are managed through the same panel UI, with per-client traffic tracking and real-time stats.

## What's New

### L2TP/IPsec Protocol Support

- **Full panel integration** — Create L2TP inbounds from the protocol dropdown, add/remove users with username and password
- **IPsec encryption** — Optional IPsec with configurable pre-shared key (PSK)
- **Xray routing** — L2TP traffic passes through Xray's routing rules via TPROXY + dokodemo-door bridge
- **Per-client traffic tracking** — Upload/download bytes tracked per user via nftables accounting
- **Client management** — Traffic limits, expiry dates, enable/disable, IP limits — same as any other protocol
- **Real-time stats** — Traffic counters update every 10 seconds, online status displayed in the UI

### PPTP Protocol Support

- **Full panel integration** — Create PPTP inbounds from the protocol dropdown, same UI as L2TP
- **No IPsec** — PPTP uses MPPE encryption (MSCHAPv2 + 128-bit MPPE), no IPsec/PSK needed
- **Xray routing** — Same TPROXY + dokodemo-door bridge as L2TP
- **Per-client traffic tracking** — Same nftables accounting mechanism via `pptp_acct` chain
- **Client management** — Traffic limits, expiry dates, enable/disable, bulk creation — same as L2TP
- **Separate subnets** — PPTP uses `10.1.x.0/24` (L2TP uses `10.0.x.0/24`)

### OpenVPN Protocol Support

- **Full panel integration** — Create OpenVPN inbounds from the protocol dropdown, same user management UI
- **Dual protocol** — Each inbound runs two OpenVPN instances: UDP (default 1194) and TCP (configurable port)
- **Certificate management** — Generate self-signed CA + server cert + tls-crypt key from the panel, or paste your own
- **Client config download** — Download `.ovpn` files (UDP or TCP) directly from the panel
- **Direct NAT routing** — OpenVPN traffic is NATed directly to the internet (no Xray/TPROXY)
- **Per-client traffic tracking** — Same nftables accounting as L2TP/PPTP
- **Separate subnets** — UDP uses `10.2.x.0/24`, TCP uses `10.3.x.0/24`

### Embedded RADIUS Server

Authentication and session management for L2TP, PPTP, and OpenVPN use an embedded RADIUS server (Go, `layeh.com/radius`) running on `127.0.0.1:1812-1813`:

- **Live auth** — pppd authenticates via RADIUS (MS-CHAPv2 for L2TP/PPTP, PAP for OpenVPN), which queries SQLite in real time — no flat credential files to regenerate
- **Session lifecycle** — RADIUS Acct-Start/Stop events create and remove per-client nftables accounting counters automatically
- **Disable = instant block** — Disabling a client in the panel takes effect on the next auth attempt; active sessions are killed (PPP sessions via signal, OpenVPN via management socket)
- **Crash recovery** — If the panel restarts while PPP sessions are alive, periodic RADIUS Acct-Interim-Update re-registers them within 60 seconds

### How It Works

L2TP and PPTP are not native Xray protocols, so a bridge architecture routes their traffic through Xray. OpenVPN uses direct NAT routing (no Xray).

```
L2TP Client              PPTP Client              OpenVPN Client
    |                        |                        |
    | (UDP 1701 + IPsec)    | (TCP 1723 + GRE)      | (UDP 1194 / TCP 443)
    v                        v                        v
Libreswan (IPsec)        pptpd                   openvpn
    |                        |                        |
    v                        v                        v
xl2tpd --> pppd          pppd                    tun device
PPP (10.0.x.0/24)        PPP (10.1.x.0/24)       (10.2.x.0/24 UDP, 10.3.x.0/24 TCP)
    |                        |                        |
    | nftables TPROXY        |                        | nftables MASQUERADE
    v                        v                        v
Xray dokodemo-door       Xray dokodemo-door       Direct NAT
    |                        |                        |
    v                        v                        v
Xray Routing Engine      Xray Routing Engine       Internet
```

Each L2TP/PPTP inbound automatically gets:
- A PPP subnet derived from the configured Local IP (e.g., `10.0.2.0/24` for L2TP, `10.1.2.0/24` for PPTP)
- A TPROXY port (`12300 + inbound ID`)
- A paired dokodemo-door inbound in the Xray config with the same tag
- nftables rules to redirect PPP traffic to Xray
- Per-client nftables accounting rules (named counters) for traffic measurement

Each OpenVPN inbound automatically gets:
- Two OpenVPN server instances (UDP + TCP) with separate tun devices
- NAT masquerade rules for the OpenVPN subnets
- Per-client nftables accounting rules (same as L2TP/PPTP)
- Auth/session scripts that integrate with the embedded RADIUS server

### Per-Client Traffic Tracking

Since Xray's dokodemo-door sees all PPP traffic as a single stream without user identity, a separate mechanism tracks per-client traffic:

1. **RADIUS Acct-Start** — When a user authenticates, pppd sends a RADIUS Accounting-Start. The embedded RADIUS server:
   - Records the session (username → email → IP mapping) in memory
   - Creates per-IP nftables named counters and accounting rules in the `l2tp_acct` or `pptp_acct` chain

2. **Traffic collection** — Every 10 seconds, `XrayTrafficJob` calls `NftService.CollectAndResetTraffic()` which:
   - Atomically reads and resets all named counters via `nft -j reset counters table ip vpn`
   - Parses JSON output to map counter names to client IPs
   - Maps IPs to client emails via RADIUS session data
   - Returns separate L2TP and PPTP per-client traffic deltas

3. **RADIUS Acct-Stop** — When a user disconnects, pppd sends a RADIUS Accounting-Stop, and the server removes their session and nft counters

## Architecture Diagram

Open [`docs/architecture.html`](docs/architecture.html) in a browser to see an interactive diagram of the L2TP integration architecture.

## Prerequisites

The VPN integrations require the following packages on the server:

```bash
# Debian/Ubuntu
apt install xl2tpd ppp libreswan libradcli4   # for L2TP/IPsec
apt install pptpd                              # for PPTP
apt install openvpn                            # for OpenVPN

# The kernel must have PPP modules (l2tp_ppp, ppp_generic, ppp_mppe)
# Cloud kernels (e.g., Hetzner) may lack these — install the full kernel:
apt install linux-image-amd64

# PPTP also needs these kernel modules (loaded automatically):
# nf_conntrack_pptp, ip_gre, ppp_mppe
```

## Installation

### Build from Source

```bash
# Requirements: Go 1.26+, GCC (for CGO/SQLite)
git clone https://github.com/Sir-MmD/vpn-ui.git
cd vpn-ui
go build -o x-ui main.go
```

### Deploy

```bash
# Create directories
mkdir -p /usr/local/x-ui/bin /etc/x-ui /var/log/x-ui

# Copy binary
cp x-ui /usr/local/x-ui/

# Download Xray binary (required)
# Get the matching release from https://github.com/XTLS/Xray-core/releases
# Place as: /usr/local/x-ui/bin/xray-linux-amd64

# Run
cd /usr/local/x-ui && ./x-ui run

# Panel available at http://your-server:2053
# Default credentials: admin / admin
```

### Development

```bash
# Create local data directory
mkdir -p x-ui

# Copy and configure environment
cp .env.example .env

# Run in development mode (templates loaded from disk)
go run main.go
```

## Usage

### Creating an L2TP Inbound

1. Open the panel at `http://your-server:2053`
2. Click **Add Inbound**
3. Select **l2tp** from the Protocol dropdown
4. Configure:
   - **Port**: `1701` (standard L2TP)
   - **IP Range**: Client IP pool (e.g., `10.0.2.10-10.0.2.50`)
   - **Local IP**: Server-side tunnel IP (e.g., `10.0.2.1`)
   - **DNS 1/2**: DNS servers pushed to clients
   - **MTU**: Typically `1400` for L2TP
   - **IPsec**: Enable and set a Pre-Shared Key
5. Click **Add** to save

### Managing L2TP Users

1. Click the **+** button on the L2TP inbound row
2. Set **Username**, **Password**, and **Email** (tracking identifier)
3. Optionally set traffic limits, expiry date, IP limits
4. Click **Add Client**

Users can connect with any L2TP/IPsec client (Windows, macOS, iOS, Android, Linux) using:
- **Server**: Your server's IP address
- **Username/Password**: As configured in the panel
- **Pre-Shared Key**: The IPsec PSK from the inbound settings
- **Type**: L2TP/IPsec PSK

### Creating a PPTP Inbound

1. Open the panel at `http://your-server:2053`
2. Click **Add Inbound**
3. Select **pptp** from the Protocol dropdown
4. Configure:
   - **Port**: `1723` (standard PPTP)
   - **IP Range**: Client IP pool (e.g., `10.1.2.10-10.1.2.50`)
   - **Local IP**: Server-side tunnel IP (e.g., `10.1.2.1`)
   - **DNS 1/2**: DNS servers pushed to clients
   - **MTU**: Typically `1400` for PPTP
5. Click **Add** to save

### Managing PPTP Users

Same as L2TP — click the **+** button on the PPTP inbound row, set Username, Password, Email, and optional limits. Bulk client creation is also supported.

Users can connect with any PPTP client using:
- **Server**: Your server's IP address
- **Username/Password**: As configured in the panel
- **Type**: PPTP (no PSK needed)

### Creating an OpenVPN Inbound

1. Open the panel at `http://your-server:2053`
2. Click **Add Inbound**
3. Select **openvpn** from the Protocol dropdown
4. Configure:
   - **Port**: `1194` (UDP port, standard OpenVPN)
   - **TCP Port**: `443` (TCP port for the second instance)
   - **DNS 1/2**: DNS servers pushed to clients
   - **MTU**: Typically `1500` for OpenVPN
5. Click **Add** to save
6. Click the inbound row to expand settings, then click **Generate Self-Signed CA** to create certificates
7. Add clients with Username and Password

### Managing OpenVPN Users

Same as L2TP/PPTP — click the **+** button on the OpenVPN inbound row, set Username, Password, Email, and optional limits.

To download client configs, expand the inbound settings and click **Download UDP Config** or **Download TCP Config**. The `.ovpn` file includes all certificates and settings — users just need to import it and enter their username/password when connecting.

### Applying Xray Routing Rules

L2TP and PPTP traffic flows through Xray's routing engine. The inbound's **tag** (e.g., `inbound-1701` for L2TP, `inbound-1723` for PPTP) can be used in routing rules.

**Note**: OpenVPN traffic uses direct NAT routing and does not pass through Xray.

```json
{
  "inboundTag": ["inbound-1701", "inbound-1723"],
  "outboundTag": "block",
  "domain": ["geosite:category-ads"]
}
```

This blocks ads for all L2TP and PPTP clients, just as it would for any Xray protocol.

## Files Modified

### Backend (Go) — 11 files modified, 5 new

| File | Change |
|------|--------|
| `database/model/model.go` | `L2TP`, `PPTP`, `OPENVPN` protocol constants |
| `web/service/l2tp.go` | **New** — L2TP service: xl2tpd, Libreswan IPsec, PPP config generation |
| `web/service/pptp.go` | **New** — PPTP service: mirrors L2TP without IPsec |
| `web/service/openvpn.go` | **New** — OpenVPN service: dual UDP/TCP instances, cert gen, management socket |
| `web/service/nftables.go` | **New** — nftables service: TPROXY rules, traffic accounting, NAT, IPsec filter |
| `web/service/radius.go` | **New** — Embedded RADIUS server: MS-CHAPv2 + PAP auth, accounting, session tracking |
| `web/service/xray.go` | Skip L2TP/PPTP inbounds + inject dokodemo-door |
| `web/service/inbound.go` | Client-key switches for L2TP/PPTP/OpenVPN (password-based, like Trojan) |
| `web/service/server.go` | DB import restores L2TP + PPTP + OpenVPN configs |
| `web/controller/inbound.go` | CRUD hooks trigger L2TP/PPTP/OpenVPN config regeneration, cert/config download routes |
| `web/web.go` | L2TP + PPTP + OpenVPN + RADIUS initialization on startup |
| `web/service/tgbot.go` | Exclude L2TP/PPTP/OpenVPN from Telegram bot protocol handling |
| `web/job/xray_traffic_job.go` | Merge L2TP + PPTP + OpenVPN per-client traffic into collection pipeline |
| `main.go` | OpenVPN RADIUS client subcommands (`openvpn-auth`, `openvpn-connect`, `openvpn-disconnect`) |

### Frontend (JS) — 2 files modified

| File | Change |
|------|--------|
| `web/assets/js/model/inbound.js` | `L2tpSettings`, `L2tpUser`, `PptpSettings`, `PptpUser`, `OpenVpnSettings`, `OpenVpnUser` classes |
| `web/assets/js/model/dbinbound.js` | `isL2tp`, `isPptp`, `isOpenVpn` getters, multi-user support |

### Frontend (HTML) — 6 files modified, 3 new

| File | Change |
|------|--------|
| `web/html/form/protocol/l2tp.html` | **New** — L2TP settings form (IPsec, IP range, DNS, MTU) |
| `web/html/form/protocol/pptp.html` | **New** — PPTP settings form (IP range, DNS, MTU) |
| `web/html/form/protocol/openvpn.html` | **New** — OpenVPN settings form (TCP port, DNS, MTU, certs, config download) |
| `web/html/form/inbound.html` | Include L2TP + PPTP + OpenVPN form templates |
| `web/html/form/client.html` | Username + password fields for L2TP/PPTP/OpenVPN clients |
| `web/html/inbounds.html` | Client identification for L2TP/PPTP/OpenVPN |
| `web/html/modals/client_modal.html` | Client add/edit for L2TP/PPTP/OpenVPN |
| `web/html/modals/client_bulk_modal.html` | Bulk client creation for L2TP/PPTP/OpenVPN |

### Generated Config Files (on server at runtime)

#### L2TP

| File | Purpose |
|------|---------|
| `/etc/xl2tpd/xl2tpd.conf` | xl2tpd LNS configuration |
| `/etc/ppp/options.xl2tpd-<id>` | Per-inbound PPP options (includes `plugin radius.so`) |
| `/etc/ipsec.conf` | Libreswan IPsec connection definitions |
| `/etc/ipsec.secrets` | IPsec pre-shared keys |

#### PPTP

| File | Purpose |
|------|---------|
| `/etc/pptpd.conf` | pptpd configuration |
| `/etc/ppp/pptpd-options-<id>` | Per-inbound PPP options (includes `plugin radius.so`) |

#### RADIUS (shared by L2TP + PPTP)

| File | Purpose |
|------|---------|
| `/etc/ppp/radius/<proto>-<id>.conf` | Per-inbound RADIUS client config (NAS-Identifier, server, dictionary) |
| `/etc/ppp/radius/servers` | Shared RADIUS secret file |
| `/etc/ppp/radius/dictionary` | Self-contained RADIUS dictionary (standard + Microsoft VSAs) |

#### OpenVPN

| File | Purpose |
|------|---------|
| `/etc/openvpn/server/server-<id>-udp.conf` | Per-inbound UDP server config |
| `/etc/openvpn/server/server-<id>-tcp.conf` | Per-inbound TCP server config |
| `/etc/openvpn/server-<id>/ca.crt` | CA certificate |
| `/etc/openvpn/server-<id>/server.crt` | Server certificate |
| `/etc/openvpn/server-<id>/server.key` | Server private key |
| `/etc/openvpn/server-<id>/tc.key` | tls-crypt key |

#### nftables

| File | Purpose |
|------|---------|
| `/etc/x-ui/vpn.nft` | nftables ruleset (`table ip vpn`) loaded atomically |

## Upstream

Based on [3x-ui v2.8.10](https://github.com/MHSanaei/3x-ui) — an Xray panel with web UI, Telegram bot, subscription server, and multi-protocol support.

## License

GPL-3.0 (same as upstream 3x-ui)
