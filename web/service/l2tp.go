package service

import (
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

// L2tpService manages L2TP VPN server configuration including xl2tpd, pppd,
// Libreswan (IPsec), and nftables TPROXY rules for routing traffic through Xray.
type L2tpService struct {
	inboundService InboundService
	nftService     NftService
	radiusService  RadiusService
	radiusSecret   string
}

// l2tpSettings represents the L2TP-specific settings stored in the inbound's Settings JSON.
type l2tpSettings struct {
	IpsecEnable    bool         `json:"ipsecEnable"`
	IpsecPsk       string       `json:"ipsecPsk"`
	AllowRaw       bool         `json:"allowRaw"`
	ClientToClient bool         `json:"clientToClient"`
	CrossInbound   bool         `json:"crossInbound"`
	IpRanges       []string     `json:"ipRanges"`
	IpRange        string       `json:"ipRange"` // legacy single-range field (read-only fallback)
	LocalIp        string       `json:"localIp"`
	Dns1           string       `json:"dns1"`
	Dns2           string       `json:"dns2"`
	Mtu            int          `json:"mtu"`
	Clients        []l2tpClient `json:"clients"`
}

type l2tpClient struct {
	ID       string `json:"id"`       // L2TP username
	Password string `json:"password"` // L2TP password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius configures the RADIUS service and shared secret for L2TP authentication.
func (s *L2tpService) SetRadius(rs RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

// getRadiusSecret returns the RADIUS secret, falling back to reading from DB
// when the in-memory field is empty (e.g. in the controller's zero-value instance).
func (s *L2tpService) getRadiusSecret() string {
	if s.radiusSecret != "" {
		return s.radiusSecret
	}
	var settingService SettingService
	secret, _ := settingService.GetRadiusSecret()
	return secret
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

// effectiveRanges returns the inbound's configured IP ranges, seeding from the
// legacy single ipRange field when the ipRanges list is empty.
func (o *l2tpSettings) effectiveRanges() []string {
	if len(o.IpRanges) > 0 {
		return o.IpRanges
	}
	if o.IpRange != "" {
		return []string{o.IpRange}
	}
	return nil
}

// GetSubnetsForInbound returns every /24 prefix ("10.0.x") the inbound's client
// ranges cover. Falls back to the legacy id-derived /24 when nothing is stored.
func (s *L2tpService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	if settings, err := s.parseSettings(inbound); err == nil {
		if subs := subnetsOf(settings.effectiveRanges()); len(subs) > 0 {
			return subs
		}
	}
	return []string{fmt.Sprintf("10.0.%d", inbound.Id)}
}

// GetSubnetForInbound returns the inbound's first /24 subnet (legacy callers).
func (s *L2tpService) GetSubnetForInbound(inbound *model.Inbound) string {
	return s.GetSubnetsForInbound(inbound)[0]
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
	if err := s.GenerateIPsecConfig(inbounds); err != nil {
		return err
	}
	radiusSecret := s.getRadiusSecret()
	for _, inbound := range inbounds {
		if err := s.GeneratePPPOptions(inbound); err != nil {
			return err
		}
		if radiusSecret != "" {
			if err := GenerateRadiusClientConfig("l2tp", inbound.Id, radiusSecret); err != nil {
				return err
			}
		}
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

		ranges := settings.effectiveRanges()
		if len(ranges) == 0 {
			subnet := s.GetSubnetForInbound(inbound)
			ranges = []string{defaultRange(subnet)}
		}
		// The PPP gateway (local ip) is the first range's .1; per-link /32
		// point-to-point addressing means one gateway serves all client /24s.
		localIp := settings.LocalIp
		if start, _, ok := parseRange(ranges[0]); ok {
			localIp = fmt.Sprintf("%d.%d.%d.1", start[0], start[1], start[2])
		}

		b.WriteString("[lns default]\n")
		// xl2tpd accepts multiple `ip range` lines; each range's client IP is then
		// pinned deterministically by RADIUS (Framed-IP-Address).
		for _, r := range ranges {
			b.WriteString(fmt.Sprintf("ip range = %s\n", r))
		}
		b.WriteString(fmt.Sprintf("local ip = %s\n", localIp))
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
	b.WriteString("refuse-pap\n")
	b.WriteString("refuse-chap\n")
	b.WriteString("require-mschap-v2\n")
	b.WriteString("ipcp-accept-local\n")
	b.WriteString("ipcp-accept-remote\n")
	b.WriteString("noccp\n")
	// Disable IPv6CP so no IPv6 address/route is negotiated on the ppp link.
	// The VPN data path (nftables TPROXY -> Xray) is IPv4-only; without this,
	// a dual-stack client could negotiate IPv6 and leak IPv6 traffic and DNS
	// straight out the host's default route, bypassing Xray entirely.
	b.WriteString("noipv6\n")
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns1))
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns2))
	b.WriteString("proxyarp\n")
	b.WriteString("lcp-echo-interval 30\n")
	b.WriteString("lcp-echo-failure 4\n")
	b.WriteString("connect-delay 5000\n")
	b.WriteString(fmt.Sprintf("mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("mru %d\n", mtu))
	b.WriteString("nodefaultroute\n")
	b.WriteString("plugin radius.so\n")
	b.WriteString(fmt.Sprintf("radius-config-file /etc/ppp/radius/l2tp-%d.conf\n", inbound.Id))

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
	// IKE (phase 1) proposals — widest client compatibility. modp2048/modp1536
	// and the ECP groups (dh19/dh20) are in every Libreswan; modp1024 (DH2) is
	// only present in an ALL_ALGS=true build. Libreswan rejects the WHOLE
	// connection if the proposal names a group it doesn't support, so modp1024
	// is appended only when the installed Libreswan actually has it — otherwise
	// stock/distro Libreswan (which x-ui setup installs) fails to load the conn.
	ike := "aes256-sha2;modp2048,aes128-sha2;modp2048,aes256-sha1;modp2048,aes128-sha1;modp2048,3des-sha1;modp2048," +
		"aes256-sha2;modp1536,aes128-sha2;modp1536,aes256-sha1;modp1536,aes128-sha1;modp1536,3des-sha1;modp1536,3des-md5;modp1536," +
		"aes256-sha2;dh20,aes256-sha2;dh19,aes128-sha2;dh19"
	if ipsecSupportsModp1024() {
		ike += ",aes256-sha2;modp1024,aes128-sha2;modp1024,aes256-sha1;modp1024,aes128-sha1;modp1024,3des-sha1;modp1024,3des-md5;modp1024"
	}
	b.WriteString("    ike=" + ike + "\n")
	// ESP (Phase 2) proposals: SHA2 + SHA1 + MD5 for widest compatibility
	b.WriteString("    phase2alg=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,3des-sha1,aes256-md5,aes128-md5,3des-md5\n")
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

// ipsecSupportsModp1024 reports whether the installed Libreswan supports the
// MODP1024 (DH2) group. Distro/stock Libreswan omits it (it's cryptographically
// weak — only a build with ALL_ALGS=true has it), and naming an unsupported
// group in a proposal makes Libreswan reject the whole connection. The selftest
// aborts (and thus reports "not supported") if the NSS DB isn't initialized,
// which safely errs toward dropping modp1024.
func ipsecSupportsModp1024() bool {
	out, _ := exec.Command("ipsec", "pluto", "--selftest").CombinedOutput()
	return strings.Contains(strings.ToUpper(string(out)), "MODP1024")
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

// RestartServices (re)launches xl2tpd as a panel-managed child process and, when
// any inbound needs it, restarts the host's IPsec (libreswan) service.
func (s *L2tpService) RestartServices() error {
	migrateFromSystemd()

	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		procMgr.Stop("xl2tpd")
		return nil
	}

	// xl2tpd -D runs in the foreground reading /etc/xl2tpd/xl2tpd.conf; the panel
	// supervises it and reaps its pppd children.
	os.MkdirAll("/var/run/xl2tpd", 0755)
	if err := procMgr.Start("xl2tpd", daemonBin("xl2tpd"), []string{"-D"}, pppdEnv(), ""); err != nil {
		logger.Warning("L2TP: failed to start xl2tpd:", err)
	}

	// IPsec (libreswan) remains a host service — it is not a bundled daemon.
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

// StopServices stops the L2TP (xl2tpd) child process.
func (s *L2tpService) StopServices() {
	procMgr.Stop("xl2tpd")
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

// KillDisabledSessions kills active PPP sessions for clients that are no longer
// allowed to connect (disabled in settings or disabled in client_traffics).
// Uses RADIUS session data to find active sessions.
func (s *L2tpService) KillDisabledSessions() {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

	// Collect emails of clients that should NOT be active
	disabled := make(map[string]bool)
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				disabled[client.Email] = true
			}
		}
	}

	if len(disabled) > 0 {
		s.radiusService.KillSessionsByEmail(disabled)
	}
}

// DisableClients enforces limits for the given client emails by killing their active PPP sessions.
// RADIUS handles auth live from the database, so no config regeneration is needed.
func (s *L2tpService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}

	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	s.radiusService.KillSessionsByEmail(emailSet)
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
