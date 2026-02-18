package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
)

// L2tpService manages L2TP VPN server configuration including xl2tpd, pppd,
// Libreswan (IPsec), and nftables TPROXY rules for routing traffic through Xray.
type L2tpService struct {
	inboundService InboundService
	nftService     NftService
}

// l2tpSettings represents the L2TP-specific settings stored in the inbound's Settings JSON.
type l2tpSettings struct {
	IpsecEnable bool         `json:"ipsecEnable"`
	IpsecPsk    string       `json:"ipsecPsk"`
	AllowRaw    bool         `json:"allowRaw"`
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
		b.WriteString("length bit = yes\n")
		b.WriteString("flow bit = yes\n\n")
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
	b.WriteString(fmt.Sprintf("name l2tp-%d\n", inbound.Id))
	b.WriteString("+mschap-v2\n")
	b.WriteString("ipcp-accept-local\n")
	b.WriteString("ipcp-accept-remote\n")
	b.WriteString("noccp\n")
	b.WriteString("auth\n")
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns1))
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns2))
	b.WriteString("proxyarp\n")
	b.WriteString("lcp-echo-interval 30\n")
	b.WriteString("lcp-echo-failure 4\n")
	b.WriteString("connect-delay 5000\n")
	b.WriteString(fmt.Sprintf("mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("mru %d\n", mtu))
	b.WriteString("nodefaultroute\n")

	return s.writeFile(fmt.Sprintf("/etc/ppp/options.xl2tpd-%d", inbound.Id), b.String())
}

// getDisabledEmails returns a set of client emails that are disabled in the
// client_traffics table (due to traffic limit or expiry).
func (s *L2tpService) getDisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := database.GetDB()
	var emails []string
	db.Model(&xray.ClientTraffic{}).
		Where("enable = ?", false).
		Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// GenerateChapSecrets writes /etc/ppp/chap-secrets from all L2TP and PPTP inbound clients.
// Both protocols share this file; the "server" column distinguishes them.
// Clients disabled by admin (Enable=false in settings) or by the system
// (enable=false in client_traffics, due to traffic/expiry limits) are excluded.
func (s *L2tpService) GenerateChapSecrets(inbounds []*model.Inbound) error {
	disabledEmails := s.getDisabledEmails()

	var b strings.Builder
	b.WriteString("# Auto-generated by 3x-ui PPP service\n")
	b.WriteString("# client    server       secret       IP\n")

	// L2TP entries
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		serverName := fmt.Sprintf("l2tp-%d", inbound.Id)
		for _, client := range settings.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				continue
			}
			b.WriteString(fmt.Sprintf("%s    %s    %s    *\n", client.ID, serverName, client.Password))
		}
	}

	// PPTP entries (shared chap-secrets file)
	db := database.GetDB()
	var pptpInbounds []*model.Inbound
	db.Model(model.Inbound{}).Where("protocol = ?", "pptp").Find(&pptpInbounds)

	for _, inbound := range pptpInbounds {
		pptpS := &pptpSettings{}
		if err := json.Unmarshal([]byte(inbound.Settings), pptpS); err != nil {
			continue
		}
		serverName := fmt.Sprintf("pptp-%d", inbound.Id)
		for _, client := range pptpS.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				continue
			}
			b.WriteString(fmt.Sprintf("%s    %s    %s    *\n", client.ID, serverName, client.Password))
		}
	}

	return s.writeFile("/etc/ppp/chap-secrets", b.String())
}

// GenerateIPsecConfig writes /etc/ipsec.conf and /etc/ipsec.secrets for L2TP/IPsec.
// Uses Libreswan format which provides better compatibility across Windows, iOS, and Linux.
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

	// Libreswan ipsec.conf format
	var b strings.Builder
	b.WriteString("# Auto-generated by 3x-ui L2TP service — do not edit\n")
	b.WriteString("config setup\n")
	b.WriteString("    uniqueids=no\n")
	b.WriteString("    logfile=/var/log/pluto.log\n")
	b.WriteString("    ikev1-policy=accept\n")
	b.WriteString("\n")
	b.WriteString("conn l2tp-psk\n")
	b.WriteString("    auto=add\n")
	b.WriteString("    leftprotoport=17/1701\n")
	b.WriteString("    rightprotoport=17/%any\n")
	b.WriteString("    type=transport\n")
	b.WriteString("    authby=secret\n")
	b.WriteString("    pfs=no\n")
	b.WriteString("    rekey=no\n")
	b.WriteString("    dpddelay=40\n")
	b.WriteString("    dpdtimeout=130\n")
	b.WriteString("    keyexchange=ikev1\n")
	// IKE proposals: broad coverage for Windows 10/11 (MODP2048+SHA1/SHA2), iOS (ECP DH19/DH20+SHA2), Linux
	b.WriteString("    ike=aes256-sha2;modp2048,aes128-sha2;modp2048,aes256-sha1;modp2048,aes128-sha1;modp2048,3des-sha1;modp2048,aes256-sha2;dh20,aes256-sha2;dh19,aes128-sha2;dh19\n")
	// ESP (Phase 2) proposals: SHA2-256 (128-bit) + SHA1 (96-bit) for all OSes
	b.WriteString("    phase2alg=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,3des-sha1\n")
	b.WriteString("    left=%defaultroute\n")
	b.WriteString("    right=%any\n")

	if err := s.writeFile("/etc/ipsec.conf", b.String()); err != nil {
		return err
	}

	// Write /etc/ipsec.secrets (mode 0600 for PSK confidentiality)
	escapedPsk := strings.ReplaceAll(psks[0], `\`, `\\`)
	escapedPsk = strings.ReplaceAll(escapedPsk, `"`, `\"`)
	secrets := fmt.Sprintf(": PSK \"%s\"\n", escapedPsk)
	if err := s.writeFileMode("/etc/ipsec.secrets", secrets, 0600); err != nil {
		return err
	}

	// Clean up old StrongSwan swanctl config if present
	os.Remove("/etc/swanctl/conf.d/l2tp.conf")

	return nil
}

// SetupAllTproxy sets up kernel modules, ip rules, and nftables rules for TPROXY.
func (s *L2tpService) SetupAllTproxy() error {
	// Enable IP forwarding
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Load kernel modules
	s.runCmd("modprobe", "l2tp_ppp")
	s.runCmd("modprobe", "ppp_generic")
	s.runCmd("modprobe", "af_key")
	s.runCmd("modprobe", "nf_tproxy_ipv4")

	// Set up ip rule and route table (check if already exists to avoid duplicates)
	output, _ := exec.Command("ip", "rule", "show").Output()
	if !strings.Contains(string(output), "fwmark 0x1 lookup 100") {
		s.runCmd("ip", "rule", "add", "fwmark", "1", "lookup", "100")
	}
	s.runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	return s.nftService.ApplyNftRules()
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
			// Libreswan reads /etc/ipsec.conf on restart automatically
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

	s.nftService.CleanupLegacyIptables()

	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("L2TP: failed to generate configs:", err)
		return
	}
	if err := s.SetupAllTproxy(); err != nil {
		logger.Warning("L2TP: failed to setup TPROXY:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("L2TP: failed to restart services:", err)
	}
}

// GenerateUserMap writes /etc/x-ui/l2tp-usermap with username→email mappings
// so the ip-up script can look up the email for a connecting user.
// Clients disabled in client_traffics (traffic/expiry) are excluded.
func (s *L2tpService) GenerateUserMap() error {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	disabledEmails := s.getDisabledEmails()

	var b strings.Builder
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if client.Enable && client.Email != "" && !disabledEmails[client.Email] {
				// Format: username email
				b.WriteString(fmt.Sprintf("%s %s\n", client.ID, client.Email))
			}
		}
	}

	return s.writeFile(l2tpUserMapFile, b.String())
}

// GenerateIpUpDown writes the pppd ip-up.d and ip-down.d scripts for session tracking.
// ip-up: records username→IP mapping and adds nft accounting counters/rules
// ip-down: removes the mapping and nft accounting counters/rules
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

# Look up email from usermap — exit if user is not an L2TP client
USERMAP="` + l2tpUserMapFile + `"
[ ! -f "$USERMAP" ] && exit 0
EMAIL=$(awk -v u="$USERNAME" '$1 == u {print $2; exit}' "$USERMAP")
[ -z "$EMAIL" ] && exit 0

# Record session: email IP interface
SESSIONS="` + l2tpSessionsFile + `"
# Remove any stale entry for this IP first
grep -v " $REMOTE_IP " "$SESSIONS" 2>/dev/null > "$SESSIONS.tmp" || true
echo "$EMAIL $REMOTE_IP $IFACE" >> "$SESSIONS.tmp"
mv "$SESSIONS.tmp" "$SESSIONS"

# Add nft counters and accounting rules
COUNTER_IP=$(echo "$REMOTE_IP" | tr '.' '_')
nft add counter ip vpn "l2tp_up_${COUNTER_IP}" 2>/dev/null
nft add counter ip vpn "l2tp_down_${COUNTER_IP}" 2>/dev/null
if ! nft list chain ip vpn l2tp_acct 2>/dev/null | grep -q "addr ${REMOTE_IP} "; then
    nft add rule ip vpn l2tp_acct ip saddr "$REMOTE_IP" counter name "l2tp_up_${COUNTER_IP}"
    nft add rule ip vpn l2tp_acct ip daddr "$REMOTE_IP" counter name "l2tp_down_${COUNTER_IP}"
fi
`

	// ip-down.d script
	ipDown := `#!/bin/sh
# Auto-generated by 3x-ui L2TP service — do not edit
REMOTE_IP="$5"

[ -z "$REMOTE_IP" ] && exit 0

# Only process if this IP is in L2TP sessions
SESSIONS="` + l2tpSessionsFile + `"
[ ! -f "$SESSIONS" ] && exit 0
grep -q " $REMOTE_IP " "$SESSIONS" || exit 0

# Remove session entry
grep -v " $REMOTE_IP " "$SESSIONS" > "$SESSIONS.tmp" || true
mv "$SESSIONS.tmp" "$SESSIONS"

# Remove nft accounting rules and counters
COUNTER_IP=$(echo "$REMOTE_IP" | tr '.' '_')
nft -a list chain ip vpn l2tp_acct 2>/dev/null | grep "addr ${REMOTE_IP} " | while IFS= read -r line; do
    handle=$(echo "$line" | sed -n 's/.*# handle \([0-9]*\).*/\1/p')
    [ -n "$handle" ] && nft delete rule ip vpn l2tp_acct handle "$handle" 2>/dev/null
done
nft delete counter ip vpn "l2tp_up_${COUNTER_IP}" 2>/dev/null
nft delete counter ip vpn "l2tp_down_${COUNTER_IP}" 2>/dev/null
`

	if err := s.writeFileMode("/etc/ppp/ip-up.d/l2tp-acct", ipUp, 0755); err != nil {
		return err
	}
	return s.writeFileMode("/etc/ppp/ip-down.d/l2tp-acct", ipDown, 0755)
}

// l2tpSession holds a parsed line from the L2TP sessions file.
type l2tpSession struct {
	Email     string
	IP        string
	Interface string
}

// readSessionList reads the L2TP sessions file and returns all sessions.
func (s *L2tpService) readSessionList() []l2tpSession {
	data, err := os.ReadFile(l2tpSessionsFile)
	if err != nil {
		return nil
	}

	var sessions []l2tpSession
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) >= 3 {
			sessions = append(sessions, l2tpSession{
				Email:     fields[0],
				IP:        fields[1],
				Interface: fields[2],
			})
		}
	}
	return sessions
}

// readSessions reads the L2TP sessions file and returns a map of email → IP.
func (s *L2tpService) readSessions() map[string]string {
	sessions := make(map[string]string)
	for _, sess := range s.readSessionList() {
		sessions[sess.Email] = sess.IP
	}
	return sessions
}

// KillDisabledSessions kills active PPP sessions for clients that are no longer
// allowed to connect (disabled in settings or disabled in client_traffics).
func (s *L2tpService) KillDisabledSessions() {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

	// Collect emails of clients that should be active
	allowed := make(map[string]bool)
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if client.Enable && !disabledEmails[client.Email] {
				allowed[client.Email] = true
			}
		}
	}

	// Kill sessions for clients NOT in the allowed set
	for _, sess := range s.readSessionList() {
		if !allowed[sess.Email] && sess.Interface != "" {
			pidFile := fmt.Sprintf("/var/run/%s.pid", sess.Interface)
			pidData, err := os.ReadFile(pidFile)
			if err == nil {
				pid := strings.TrimSpace(string(pidData))
				if pid != "" {
					s.runCmd("kill", pid)
					logger.Infof("L2TP: killed disabled session %s (email=%s, ip=%s)", sess.Interface, sess.Email, sess.IP)
				}
			}
		}
	}
}

// DisableClients enforces limits for the given client emails:
// kills their active PPP sessions, regenerates chap-secrets (which will
// exclude them), and updates the user map.
func (s *L2tpService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}

	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	// Kill active PPP sessions for these clients
	for _, sess := range s.readSessionList() {
		if emailSet[sess.Email] && sess.Interface != "" {
			pidFile := fmt.Sprintf("/var/run/%s.pid", sess.Interface)
			pidData, err := os.ReadFile(pidFile)
			if err == nil {
				pid := strings.TrimSpace(string(pidData))
				if pid != "" {
					s.runCmd("kill", pid)
					logger.Infof("L2TP: killed session %s (email=%s, ip=%s)", sess.Interface, sess.Email, sess.IP)
				}
			}
		}
	}

	// Regenerate chap-secrets and usermap (disabled clients will be excluded)
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		logger.Warning("L2TP: failed to get inbounds for DisableClients:", err)
		return
	}
	if err := s.GenerateChapSecrets(inbounds); err != nil {
		logger.Warning("L2TP: failed to regenerate chap-secrets:", err)
	}
	if err := s.GenerateUserMap(); err != nil {
		logger.Warning("L2TP: failed to regenerate usermap:", err)
	}
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
