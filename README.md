# VPN-UI (3x-ui + L2TP/IPsec)

A fork of [3x-ui](https://github.com/MHSanaei/3x-ui) that adds **L2TP/IPsec** as a first-class inbound protocol alongside the existing Xray protocols (VMess, VLESS, Trojan, Shadowsocks, etc.).

L2TP/IPsec clients are managed through the same panel UI, their traffic is routed through Xray's routing engine, and per-client traffic is tracked and displayed in real time.

## What's New

### L2TP/IPsec Protocol Support

- **Full panel integration** — Create L2TP inbounds from the protocol dropdown, add/remove users with username and password
- **IPsec encryption** — Optional IPsec with configurable pre-shared key (PSK)
- **Xray routing** — L2TP traffic passes through Xray's routing rules via TPROXY + dokodemo-door bridge
- **Per-client traffic tracking** — Upload/download bytes tracked per user via iptables accounting
- **Client management** — Traffic limits, expiry dates, enable/disable, IP limits — same as any other protocol
- **Real-time stats** — Traffic counters update every 10 seconds, online status displayed in the UI

### How It Works

L2TP is not a native Xray protocol, so a bridge architecture routes L2TP traffic through Xray:

```
L2TP Client
    |
    | (UDP 1701, encrypted with IPsec)
    v
strongSwan (IPsec) --> xl2tpd --> pppd --> PPP interface (10.0.x.0/24)
                                              |
                                              | iptables TPROXY (mangle)
                                              v
                                    Xray dokodemo-door (port 123xx)
                                              |
                                              v
                                    Xray Routing Engine
                                              |
                                    +---------+---------+
                                    |         |         |
                                  Direct   Proxy    Block
```

Each L2TP inbound automatically gets:
- A PPP subnet derived from the configured Local IP (e.g., `10.0.2.0/24`)
- A TPROXY port (`12300 + inbound ID`)
- A paired dokodemo-door inbound in the Xray config with the same tag
- iptables rules to redirect PPP traffic to Xray
- Per-client iptables accounting rules for traffic measurement

### Per-Client Traffic Tracking

Since Xray's dokodemo-door sees all PPP traffic as a single stream without user identity, a separate mechanism tracks per-client traffic:

1. **pppd ip-up hook** — When a user authenticates via CHAP, pppd runs `/etc/ppp/ip-up.d/l2tp-acct` which:
   - Looks up the user's email from `/etc/x-ui/l2tp-usermap`
   - Records `email IP interface` in `/etc/x-ui/l2tp-sessions`
   - Adds per-IP iptables accounting rules in the `L2TP_ACCT` chain

2. **Traffic collection** — Every 10 seconds, `XrayTrafficJob` calls `CollectL2tpTraffic()` which:
   - Reads the sessions file to map IPs to client emails
   - Reads iptables byte counters from the `L2TP_ACCT` chain
   - Zeros the counters after reading
   - Returns per-client traffic deltas that feed into the existing traffic pipeline

3. **pppd ip-down hook** — When a user disconnects, `/etc/ppp/ip-down.d/l2tp-acct` removes their session entry

## Architecture Diagram

Open [`docs/architecture.html`](docs/architecture.html) in a browser to see an interactive diagram of the L2TP integration architecture.

## Prerequisites

The L2TP integration requires the following packages on the server:

```bash
# Debian/Ubuntu
apt install xl2tpd ppp strongswan

# The kernel must have PPP modules (l2tp_ppp, ppp_generic)
# Cloud kernels (e.g., Hetzner) may lack these — install the full kernel:
apt install linux-image-amd64
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

### Applying Xray Routing Rules

L2TP traffic flows through Xray's routing engine. The L2TP inbound's **tag** (e.g., `inbound-1701`) can be used in routing rules:

```json
{
  "inboundTag": ["inbound-1701"],
  "outboundTag": "block",
  "domain": ["geosite:category-ads"]
}
```

This blocks ads for all L2TP clients, just as it would for any Xray protocol.

## Files Modified

### Backend (Go) — 8 files modified, 1 new

| File | Change |
|------|--------|
| `database/model/model.go` | `L2TP` protocol constant |
| `web/service/l2tp.go` | **New** — L2TP service: config generation, TPROXY, traffic accounting |
| `web/service/xray.go` | Skip L2TP inbounds + inject dokodemo-door |
| `web/service/inbound.go` | Client-key switches for L2TP (password-based, like Trojan) |
| `web/controller/inbound.go` | CRUD hooks trigger L2TP config regeneration |
| `web/web.go` | L2TP initialization on startup |
| `web/service/tgbot.go` | Exclude L2TP from Telegram bot protocol handling |
| `web/job/xray_traffic_job.go` | Merge L2TP per-client traffic into collection pipeline |

### Frontend (JS) — 2 files modified

| File | Change |
|------|--------|
| `web/assets/js/model/inbound.js` | `L2tpSettings` class, `L2tpUser` class, protocol constants |
| `web/assets/js/model/dbinbound.js` | `isL2tp` getter, multi-user support |

### Frontend (HTML) — 5 files modified, 1 new

| File | Change |
|------|--------|
| `web/html/form/protocol/l2tp.html` | **New** — L2TP settings form (IPsec, IP range, DNS, MTU) |
| `web/html/form/inbound.html` | Include L2TP form template |
| `web/html/form/client.html` | Username + password fields for L2TP clients |
| `web/html/inbounds.html` | Client identification for L2TP |
| `web/html/modals/client_modal.html` | Client add/edit for L2TP |

### Generated Config Files (on server at runtime)

| File | Purpose |
|------|---------|
| `/etc/xl2tpd/xl2tpd.conf` | xl2tpd LNS configuration |
| `/etc/ppp/options.xl2tpd-<id>` | Per-inbound PPP options |
| `/etc/ppp/chap-secrets` | L2TP user credentials |
| `/etc/ipsec.conf` | IPsec connection definitions |
| `/etc/ipsec.secrets` | IPsec pre-shared keys |
| `/etc/x-ui/l2tp-usermap` | Username-to-email mapping |
| `/etc/x-ui/l2tp-sessions` | Active session tracking |
| `/etc/ppp/ip-up.d/l2tp-acct` | Session start hook |
| `/etc/ppp/ip-down.d/l2tp-acct` | Session end hook |

## Upstream

Based on [3x-ui v2.8.10](https://github.com/MHSanaei/3x-ui) — an Xray panel with web UI, Telegram bot, subscription server, and multi-protocol support.

## License

GPL-3.0 (same as upstream 3x-ui)
