package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

const (
	l2tpSessionsFile = "/etc/x-ui/l2tp-sessions"
	l2tpUserMapFile  = "/etc/x-ui/l2tp-usermap"
	l2tpAcctChain    = "L2TP_ACCT"
)

// L2tpService manages L2TP VPN server configuration including xl2tpd, pppd,
// strongSwan (IPsec), and iptables TPROXY rules for routing traffic through Xray.
type L2tpService struct {
	inboundService InboundService
}

// l2tpSettings represents the L2TP-specific settings stored in the inbound's Settings JSON.
type l2tpSettings struct {
	IpsecEnable bool         `json:"ipsecEnable"`
	IpsecPsk    string       `json:"ipsecPsk"`
	IpRange     string       `json:"ipRange"`
	LocalIp     string       `json:"localIp"`
	Dns1        string       `json:"dns1"`
	Dns2        string       `json:"dns2"`
	Mtu         int          `json:"mtu"`
	Clients     []l2tpClient `json:"clients"`
}

type l2tpClient struct {
	ID       string `json:"id"`       // L2TP username
	Password string `json:"password"` // L2TP password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

func (s *L2tpService) GetL2tpInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "l2tp").Find(&inbounds).Error
	return inbounds, err
}

func (s *L2tpService) parseSettings(inbound *model.Inbound) (*l2tpSettings, error) {
	settings := &l2tpSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	if err != nil {
		return nil, fmt.Errorf("failed to parse L2TP settings for inbound %d: %w", inbound.Id, err)
	}
	return settings, nil
}

// GetSubnetForInbound extracts the /24 subnet from the inbound's localIp setting.
// Falls back to a deterministic 10.0.x.0/24 subnet if localIp is not set.
func (s *L2tpService) GetSubnetForInbound(inbound *model.Inbound) string {
	settings, err := s.parseSettings(inbound)
	if err == nil && settings.LocalIp != "" {
		// Extract first 3 octets from localIp (e.g., "10.0.2.1" -> "10.0.2")
		parts := strings.Split(settings.LocalIp, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
		}
	}
	octet := 2 + (inbound.Id % 250)
	return fmt.Sprintf("10.0.%d", octet)
}

// GetTproxyPort returns a deterministic TPROXY port for the given inbound.
func (s *L2tpService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound config for Xray.
// This config captures TPROXY-redirected PPP traffic and feeds it into Xray's routing.
func (s *L2tpService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
	port := s.GetTproxyPort(inbound)
	settings := `{"network":"tcp,udp","followRedirect":true}`
	streamSettings := `{"sockopt":{"tproxy":"tproxy","mark":255}}`
	sniffing := `{"enabled":true,"destOverride":["http","tls"]}`

	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(`"0.0.0.0"`),
		Port:           port,
		Protocol:       "dokodemo-door",
		Settings:       json_util.RawMessage(settings),
		StreamSettings: json_util.RawMessage(streamSettings),
		Tag:            inbound.Tag,
		Sniffing:       json_util.RawMessage(sniffing),
	}
}

// GenerateAllConfigs regenerates all L2TP-related config files from the database state.
func (s *L2tpService) GenerateAllConfigs() error {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		return nil
	}

	if err := s.GenerateXl2tpdConfig(inbounds); err != nil {
		return err
	}
	if err := s.GenerateChapSecrets(inbounds); err != nil {
		return err
	}
	if err := s.GenerateIPsecConfig(inbounds); err != nil {
		return err
	}
	for _, inbound := range inbounds {
		if err := s.GeneratePPPOptions(inbound); err != nil {
			return err
		}
	}

	if err := s.GenerateUserMap(); err != nil {
		return err
	}
	if err := s.GenerateIpUpDown(); err != nil {
		return err
	}

	return nil
}

// GenerateXl2tpdConfig writes /etc/xl2tpd/xl2tpd.conf with one [lns] section per L2TP inbound.
func (s *L2tpService) GenerateXl2tpdConfig(inbounds []*model.Inbound) error {
	var b strings.Builder
	b.WriteString("[global]\n")
	b.WriteString("port = 1701\n\n")

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("L2TP: skipping inbound", inbound.Id, err)
			continue
		}

		subnet := s.GetSubnetForInbound(inbound)
		ipRange := settings.IpRange
		if ipRange == "" {
			ipRange = fmt.Sprintf("%s.10-%s.50", subnet, subnet)
		}
		localIp := settings.LocalIp
		if localIp == "" {
			localIp = fmt.Sprintf("%s.1", subnet)
		}

		b.WriteString("[lns default]\n")
		b.WriteString(fmt.Sprintf("ip range = %s\n", ipRange))
		b.WriteString(fmt.Sprintf("local ip = %s\n", localIp))
		b.WriteString("require chap = yes\n")
		b.WriteString("refuse pap = yes\n")
		b.WriteString("require authentication = yes\n")
		b.WriteString(fmt.Sprintf("name = l2tp-%d\n", inbound.Id))
		b.WriteString(fmt.Sprintf("pppoptfile = /etc/ppp/options.xl2tpd-%d\n", inbound.Id))
		b.WriteString("length bit = yes\n\n")
	}

	return s.writeFile("/etc/xl2tpd/xl2tpd.conf", b.String())
}

// GeneratePPPOptions writes per-inbound PPP options file.
func (s *L2tpService) GeneratePPPOptions(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}

	mtu := settings.Mtu
	if mtu == 0 {
		mtu = 1400
	}
	dns1 := settings.Dns1
	if dns1 == "" {
		dns1 = "8.8.8.8"
	}
	dns2 := settings.Dns2
	if dns2 == "" {
		dns2 = "8.8.4.4"
	}

	var b strings.Builder
	b.WriteString("require-mschap-v2\n")
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns1))
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns2))
	b.WriteString("auth\n")
	b.WriteString("debug\n")
	b.WriteString(fmt.Sprintf("name l2tp-%d\n", inbound.Id))
	b.WriteString("proxyarp\n")
	b.WriteString("lcp-echo-interval 30\n")
	b.WriteString("lcp-echo-failure 4\n")
	b.WriteString(fmt.Sprintf("mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("mru %d\n", mtu))
	b.WriteString("nodefaultroute\n")

	return s.writeFile(fmt.Sprintf("/etc/ppp/options.xl2tpd-%d", inbound.Id), b.String())
}

// GenerateChapSecrets writes /etc/ppp/chap-secrets from all L2TP inbound clients.
func (s *L2tpService) GenerateChapSecrets(inbounds []*model.Inbound) error {
	var b strings.Builder
	b.WriteString("# Auto-generated by 3x-ui L2TP service\n")
	b.WriteString("# client    server       secret       IP\n")

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		serverName := fmt.Sprintf("l2tp-%d", inbound.Id)
		for _, client := range settings.Clients {
			if !client.Enable {
				continue
			}
			b.WriteString(fmt.Sprintf("%s    %s    %s    *\n", client.ID, serverName, client.Password))
		}
	}

	return s.writeFile("/etc/ppp/chap-secrets", b.String())
}

// GenerateIPsecConfig writes /etc/ipsec.conf and /etc/ipsec.secrets for L2TP/IPsec.
func (s *L2tpService) GenerateIPsecConfig(inbounds []*model.Inbound) error {
	hasIpsec := false
	var psks []string

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		if settings.IpsecEnable && settings.IpsecPsk != "" {
			hasIpsec = true
			psks = append(psks, settings.IpsecPsk)
		}
	}

	if !hasIpsec {
		return nil
	}

	// ipsec.conf
	var b strings.Builder
	b.WriteString("# Auto-generated by 3x-ui L2TP service\n")
	b.WriteString("config setup\n")
	b.WriteString("    charondebug=\"ike 1, knl 1, cfg 1\"\n")
	b.WriteString("    uniqueids=no\n\n")
	b.WriteString("conn l2tp-psk\n")
	b.WriteString("    authby=secret\n")
	b.WriteString("    auto=add\n")
	b.WriteString("    keyingtries=3\n")
	b.WriteString("    rekey=no\n")
	b.WriteString("    ikelifetime=8h\n")
	b.WriteString("    keylife=1h\n")
	b.WriteString("    type=transport\n")
	b.WriteString("    left=%defaultroute\n")
	b.WriteString("    leftprotoport=17/1701\n")
	b.WriteString("    right=%any\n")
	b.WriteString("    rightprotoport=17/%any\n")
	b.WriteString("    dpddelay=30\n")
	b.WriteString("    dpdtimeout=120\n")
	b.WriteString("    dpdaction=clear\n")
	b.WriteString("    ike=aes256-sha256-modp2048,aes128-sha1-modp2048!\n")
	b.WriteString("    esp=aes256-sha256,aes128-sha1!\n")

	if err := s.writeFile("/etc/ipsec.conf", b.String()); err != nil {
		return err
	}

	// ipsec.secrets — use the first PSK (all L2TP inbounds share the same IPsec tunnel)
	secrets := fmt.Sprintf(": PSK \"%s\"\n", psks[0])
	return s.writeFileMode("/etc/ipsec.secrets", secrets, 0600)
}

// SetupTproxy creates iptables TPROXY rules and ip routing for a specific L2TP inbound.
func (s *L2tpService) SetupTproxy(inbound *model.Inbound) error {
	subnet := s.GetSubnetForInbound(inbound)
	port := s.GetTproxyPort(inbound)
	src := fmt.Sprintf("%s.0/24", subnet)

	// First remove any existing rules for this subnet to avoid duplicates
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
		"-s", src, "-p", "tcp", "-m", "mark", "!", "--mark", "255",
		"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
		"-s", src, "-p", "udp", "-m", "mark", "!", "--mark", "255",
		"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")

	// Add TPROXY rules for TCP and UDP
	if err := s.runCmd("iptables", "-t", "mangle", "-A", "PREROUTING",
		"-s", src, "-p", "tcp", "-m", "mark", "!", "--mark", "255",
		"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1"); err != nil {
		return fmt.Errorf("failed to add TCP TPROXY rule: %w", err)
	}
	if err := s.runCmd("iptables", "-t", "mangle", "-A", "PREROUTING",
		"-s", src, "-p", "udp", "-m", "mark", "!", "--mark", "255",
		"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1"); err != nil {
		return fmt.Errorf("failed to add UDP TPROXY rule: %w", err)
	}

	logger.Infof("L2TP: TPROXY setup for inbound %d: %s → port %d", inbound.Id, src, port)
	return nil
}

// CleanupTproxy removes iptables TPROXY rules for a specific L2TP inbound.
func (s *L2tpService) CleanupTproxy(inbound *model.Inbound) error {
	subnet := s.GetSubnetForInbound(inbound)
	port := s.GetTproxyPort(inbound)
	src := fmt.Sprintf("%s.0/24", subnet)

	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
		"-s", src, "-p", "tcp", "-m", "mark", "!", "--mark", "255",
		"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
		"-s", src, "-p", "udp", "-m", "mark", "!", "--mark", "255",
		"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")

	logger.Infof("L2TP: TPROXY cleanup for inbound %d", inbound.Id)
	return nil
}

// SetupAllTproxy sets up TPROXY for all enabled L2TP inbounds (called on startup).
func (s *L2tpService) SetupAllTproxy() error {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	// Enable IP forwarding
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Load kernel modules
	s.runCmd("modprobe", "l2tp_ppp")
	s.runCmd("modprobe", "ppp_generic")
	s.runCmd("modprobe", "af_key")
	s.runCmd("modprobe", "xt_TPROXY")

	// Set up ip rule and route table (check if already exists to avoid duplicates)
	output, _ := exec.Command("ip", "rule", "show").Output()
	if !strings.Contains(string(output), "fwmark 0x1 lookup 100") {
		s.runCmd("ip", "rule", "add", "fwmark", "1", "lookup", "100")
	}
	s.runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		if err := s.SetupTproxy(inbound); err != nil {
			logger.Warning("L2TP: failed to setup TPROXY for inbound", inbound.Id, err)
		}
	}
	return nil
}

// RestartServices restarts xl2tpd and optionally ipsec.
func (s *L2tpService) RestartServices() error {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		return nil
	}

	// Restart xl2tpd
	if err := s.runCmd("systemctl", "restart", "xl2tpd"); err != nil {
		logger.Warning("L2TP: failed to restart xl2tpd:", err)
	}

	// Check if any inbound has IPsec enabled
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		if settings.IpsecEnable {
			if err := s.runCmd("ipsec", "restart"); err != nil {
				logger.Warning("L2TP: failed to restart ipsec:", err)
			}
			break
		}
	}

	return nil
}

// InitL2tp initializes L2TP services on panel startup.
func (s *L2tpService) InitL2tp() {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	logger.Info("L2TP: initializing L2TP services for", len(inbounds), "inbound(s)")

	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("L2TP: failed to generate configs:", err)
		return
	}
	if err := s.SetupAllTproxy(); err != nil {
		logger.Warning("L2TP: failed to setup TPROXY:", err)
	}
	if err := s.SetupAcctChain(); err != nil {
		logger.Warning("L2TP: failed to setup accounting chain:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("L2TP: failed to restart services:", err)
	}
}

// GenerateUserMap writes /etc/x-ui/l2tp-usermap with username→email mappings
// so the ip-up script can look up the email for a connecting user.
func (s *L2tpService) GenerateUserMap() error {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	var b strings.Builder
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if client.Enable && client.Email != "" {
				// Format: username email
				b.WriteString(fmt.Sprintf("%s %s\n", client.ID, client.Email))
			}
		}
	}

	return s.writeFile(l2tpUserMapFile, b.String())
}

// GenerateIpUpDown writes the pppd ip-up.d and ip-down.d scripts for session tracking.
// ip-up: records username→IP mapping and adds iptables accounting rules
// ip-down: removes the mapping and accounting rules
func (s *L2tpService) GenerateIpUpDown() error {
	// Ensure directories exist
	os.MkdirAll("/etc/ppp/ip-up.d", 0755)
	os.MkdirAll("/etc/ppp/ip-down.d", 0755)

	// ip-up.d script: called by pppd with args: interface-name tty-device speed local-IP remote-IP ipparam
	// Environment: PEERNAME=authenticated_username
	ipUp := `#!/bin/sh
# Auto-generated by 3x-ui L2TP service — do not edit
IFACE="$1"
REMOTE_IP="$5"
USERNAME="$PEERNAME"

[ -z "$USERNAME" ] && exit 0
[ -z "$REMOTE_IP" ] && exit 0

# Look up email from usermap
USERMAP="` + l2tpUserMapFile + `"
EMAIL=""
if [ -f "$USERMAP" ]; then
    EMAIL=$(awk -v u="$USERNAME" '$1 == u {print $2; exit}' "$USERMAP")
fi
[ -z "$EMAIL" ] && EMAIL="$USERNAME"

# Record session: email IP interface
SESSIONS="` + l2tpSessionsFile + `"
# Remove any stale entry for this IP first
grep -v " $REMOTE_IP " "$SESSIONS" 2>/dev/null > "$SESSIONS.tmp" || true
echo "$EMAIL $REMOTE_IP $IFACE" >> "$SESSIONS.tmp"
mv "$SESSIONS.tmp" "$SESSIONS"

# Add iptables accounting rules in mangle table for this IP (upload = from client, download = to client)
iptables -t mangle -C ` + l2tpAcctChain + ` -s "$REMOTE_IP" 2>/dev/null || \
    iptables -t mangle -A ` + l2tpAcctChain + ` -s "$REMOTE_IP"
iptables -t mangle -C ` + l2tpAcctChain + ` -d "$REMOTE_IP" 2>/dev/null || \
    iptables -t mangle -A ` + l2tpAcctChain + ` -d "$REMOTE_IP"
`

	// ip-down.d script
	ipDown := `#!/bin/sh
# Auto-generated by 3x-ui L2TP service — do not edit
REMOTE_IP="$5"

[ -z "$REMOTE_IP" ] && exit 0

# Remove session entry
SESSIONS="` + l2tpSessionsFile + `"
if [ -f "$SESSIONS" ]; then
    grep -v " $REMOTE_IP " "$SESSIONS" > "$SESSIONS.tmp" || true
    mv "$SESSIONS.tmp" "$SESSIONS"
fi

# Note: we do NOT remove iptables accounting rules here.
# The panel reads counters periodically and cleans up stale rules.
`

	if err := s.writeFileMode("/etc/ppp/ip-up.d/l2tp-acct", ipUp, 0755); err != nil {
		return err
	}
	return s.writeFileMode("/etc/ppp/ip-down.d/l2tp-acct", ipDown, 0755)
}

// SetupAcctChain creates the L2TP_ACCT iptables chain in the mangle table.
// PREROUTING captures upload (client→internet, src=client IP).
// POSTROUTING captures download (Xray→client, dst=client IP).
func (s *L2tpService) SetupAcctChain() error {
	// Create chain in mangle table if it doesn't exist
	s.runCmd("iptables", "-t", "mangle", "-N", l2tpAcctChain)

	// Insert jump at the top of PREROUTING (before TPROXY rules) for upload counting
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", l2tpAcctChain)
	if err := s.runCmd("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-j", l2tpAcctChain); err != nil {
		return fmt.Errorf("failed to insert PREROUTING jump to %s: %w", l2tpAcctChain, err)
	}

	// Also jump from POSTROUTING for download counting (Xray responses back to PPP clients)
	s.runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", l2tpAcctChain)
	if err := s.runCmd("iptables", "-t", "mangle", "-I", "POSTROUTING", "1", "-j", l2tpAcctChain); err != nil {
		return fmt.Errorf("failed to insert POSTROUTING jump to %s: %w", l2tpAcctChain, err)
	}

	return nil
}

// CollectL2tpTraffic reads iptables accounting counters and maps them to client emails.
// Returns per-client traffic deltas that can be fed into InboundService.addClientTraffic().
// Counters are reset after reading (iptables -Z).
func (s *L2tpService) CollectL2tpTraffic() []*xray.ClientTraffic {
	// Read active sessions: email → IP
	sessions := s.readSessions()
	if len(sessions) == 0 {
		return nil
	}

	// Build reverse map: IP → email
	ipToEmail := make(map[string]string)
	for email, ip := range sessions {
		ipToEmail[ip] = email
	}

	// Read iptables counters then zero them (separate commands — nf_tables doesn't support -L -Z combined)
	output, err := exec.Command("iptables", "-t", "mangle", "-L", l2tpAcctChain, "-nvx").Output()
	if err != nil {
		logger.Debug("L2TP: failed to read accounting chain:", err)
		return nil
	}
	// Zero counters after reading
	exec.Command("iptables", "-t", "mangle", "-Z", l2tpAcctChain).Run()

	// Parse iptables output. Format:
	// Chain L2TP_ACCT (1 references)
	//     pkts      bytes target     prot opt in     out     source               destination
	//       42    12345            all  --  *      *       10.0.2.10            0.0.0.0/0      (upload from client)
	//       38     9876            all  --  *      *       0.0.0.0/0            10.0.2.10      (download to client)

	// Accumulate per-email: upload (src match) and download (dst match)
	emailUp := make(map[string]int64)
	emailDown := make(map[string]int64)

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		// Parse bytes (field 1)
		bytes, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		if bytes == 0 {
			continue
		}

		// iptables -nvx output with no target: pkts bytes prot opt in out source destination
		// When target is empty, fields collapse: [pkts, bytes, "all", "--", "*", "*", src, dst]
		// Source and destination are always the last two fields
		src := fields[len(fields)-2]
		dst := fields[len(fields)-1]

		// Upload: source is client IP, destination is 0.0.0.0/0
		if email, ok := ipToEmail[src]; ok && dst == "0.0.0.0/0" {
			emailUp[email] += bytes
		}
		// Download: destination is client IP, source is 0.0.0.0/0
		if email, ok := ipToEmail[dst]; ok && src == "0.0.0.0/0" {
			emailDown[email] += bytes
		}
	}

	// Build ClientTraffic slice
	var traffics []*xray.ClientTraffic
	allEmails := make(map[string]bool)
	for email := range emailUp {
		allEmails[email] = true
	}
	for email := range emailDown {
		allEmails[email] = true
	}
	for email := range allEmails {
		up := emailUp[email]
		down := emailDown[email]
		if up > 0 || down > 0 {
			traffics = append(traffics, &xray.ClientTraffic{
				Email: email,
				Up:    up,
				Down:  down,
			})
		}
	}

	if len(traffics) > 0 {
		logger.Debugf("L2TP: collected traffic for %d client(s)", len(traffics))
	}

	return traffics
}

// readSessions reads the L2TP sessions file and returns a map of email → IP.
func (s *L2tpService) readSessions() map[string]string {
	sessions := make(map[string]string)

	data, err := os.ReadFile(l2tpSessionsFile)
	if err != nil {
		return sessions
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			email := fields[0]
			ip := fields[1]
			sessions[email] = ip
		}
	}

	return sessions
}

func (s *L2tpService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0644)
}

func (s *L2tpService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *L2tpService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("L2TP: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
