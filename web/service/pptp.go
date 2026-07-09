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

// PptpService manages PPTP VPN server configuration including pptpd, pppd,
// and nftables TPROXY rules for routing traffic through Xray.
type PptpService struct {
	inboundService InboundService
	nftService     NftService
	radiusService  *RadiusService
	radiusSecret   string
}

// pptpSettings represents the PPTP-specific settings stored in the inbound's Settings JSON.
type pptpSettings struct {
	ClientToClient bool         `json:"clientToClient"`
	CrossInbound   bool         `json:"crossInbound"`
	UserLimit         int       `json:"userLimit"`         // simultaneous devices per account (1..64); 1 = legacy
	UserLimitStrategy string    `json:"userLimitStrategy"` // at the cap: "reject" (default) or "accept" (evict oldest)
	IpRanges       []string     `json:"ipRanges"`
	IpRange        string       `json:"ipRange"` // legacy single-range field (read-only fallback)
	LocalIp        string       `json:"localIp"`
	Dns1           string       `json:"dns1"`
	Dns2           string       `json:"dns2"`
	Mtu            int          `json:"mtu"`
	Clients        []pptpClient `json:"clients"`
}

type pptpClient struct {
	ID       string `json:"id"`       // PPTP username
	Password string `json:"password"` // PPTP password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius configures the RADIUS service and shared secret for PPTP authentication.
func (s *PptpService) SetRadius(rs *RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

// getRadiusSecret returns the RADIUS secret, falling back to reading from DB
// when the in-memory field is empty (e.g. in the controller's zero-value instance).
func (s *PptpService) getRadiusSecret() string {
	if s.radiusSecret != "" {
		return s.radiusSecret
	}
	var settingService SettingService
	secret, _ := settingService.GetRadiusSecret()
	return secret
}

func (s *PptpService) GetPptpInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "pptp").Find(&inbounds).Error
	return inbounds, err
}

func (s *PptpService) parseSettings(inbound *model.Inbound) (*pptpSettings, error) {
	settings := &pptpSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// effectiveRanges returns the inbound's configured IP ranges, seeding from the
// legacy single ipRange field when the ipRanges list is empty.
func (o *pptpSettings) effectiveRanges() []string {
	if len(o.IpRanges) > 0 {
		return o.IpRanges
	}
	if o.IpRange != "" {
		return []string{o.IpRange}
	}
	return nil
}

// GetSubnetsForInbound returns every /24 prefix ("10.1.x") the inbound's client
// ranges cover. Falls back to the legacy id-derived /24 when nothing is stored.
func (s *PptpService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	if settings, err := s.parseSettings(inbound); err == nil {
		if subs := subnetsOf(settings.effectiveRanges()); len(subs) > 0 {
			return subs
		}
	}
	return []string{fmt.Sprintf("10.1.%d", inbound.Id)}
}

// GetSubnetForInbound returns the inbound's first /24 subnet (legacy callers).
func (s *PptpService) GetSubnetForInbound(inbound *model.Inbound) string {
	return s.GetSubnetsForInbound(inbound)[0]
}

// GetTproxyPort returns the TPROXY port for this inbound (shared formula with L2TP).
func (s *PptpService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds a dokodemo-door inbound config for TPROXY capture.
func (s *PptpService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
	port := s.GetTproxyPort(inbound)
	settings := fmt.Sprintf(`{"network":"tcp,udp","followRedirect":true}`)
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

// GenerateAllConfigs regenerates all PPTP-related config files from the database state.
func (s *PptpService) GenerateAllConfigs() error {
	inbounds, err := s.GetPptpInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		return nil
	}

	if err := s.GeneratePptpdConfig(inbounds); err != nil {
		return err
	}
	// One shared pptpd config serves every inbound, so the PPP options + radcli
	// config are written ONCE for the whole protocol (not per inbound). Link
	// options (DNS/MTU) come from the first inbound.
	cleanupLegacyPerInboundFiles("pptpd-options", "pptp")
	if err := s.GeneratePPPOptions(inbounds[0]); err != nil {
		return err
	}
	if radiusSecret := s.getRadiusSecret(); radiusSecret != "" {
		if err := GenerateRadiusClientConfig("pptp", radiusSecret); err != nil {
			return err
		}
	}

	return nil
}

// GeneratePptpdConfig writes /etc/pptpd.conf with the PPTP inbound settings.
// GeneratePptpdConfig writes /etc/pptpd.conf. pptpd is a single daemon on one
// control port (1723) that reads ONE option/localip/remoteip — repeating them per
// inbound collides (the panel used to emit a set per inbound, so only one inbound
// worked). So ALL PPTP inbounds share a single PPP options file + one aggregated
// remoteip pool; the per-account IP is pinned by RADIUS (Framed-IP-Address), which
// resolves the account to its own inbound's pool.
func (s *PptpService) GeneratePptpdConfig(inbounds []*model.Inbound) error {
	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui PPTP service\n")

	localIp := ""
	var groups []string
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("PPTP: skipping inbound", inbound.Id, err)
			continue
		}

		ranges := settings.effectiveRanges()
		if len(ranges) == 0 {
			subnet := s.GetSubnetForInbound(inbound)
			ranges = []string{defaultRange(subnet)}
		}
		if localIp == "" {
			localIp = settings.LocalIp
			if start, _, ok := parseRange(ranges[0]); ok {
				localIp = fmt.Sprintf("%d.%d.%d.1", start[0], start[1], start[2])
			}
		}

		// pptpd remoteip is a comma-separated list of ranges in the "A.B.C.s-e"
		// shorthand (last octet after the dash), e.g. "10.1.2.10-50,10.1.3.10-250".
		for _, r := range ranges {
			if start, end, ok := parseRange(r); ok {
				groups = append(groups, fmt.Sprintf("%d.%d.%d.%d-%d", start[0], start[1], start[2], start[3], end[3]))
			}
		}
	}
	if localIp == "" {
		localIp = "10.1.2.1"
	}

	// pptpd reuses the single localip for every connection when remoteip has more
	// addresses; one localip + the aggregated remoteip pool covers all inbounds.
	b.WriteString("option /etc/ppp/pptpd-options\n")
	b.WriteString(fmt.Sprintf("localip %s\n", localIp))
	b.WriteString(fmt.Sprintf("remoteip %s\n", strings.Join(groups, ",")))

	return s.writeFile("/etc/pptpd.conf", b.String())
}

// GeneratePPPOptions writes the single shared PPP options file
// /etc/ppp/pptpd-options used by pptpd for every PPTP inbound. It carries a
// protocol-level name + RADIUS config (nas_identifier "pptp"); the RADIUS server
// maps each account to its inbound by username. DNS/MTU come from the
// representative (first) inbound — all PPTP inbounds share these link options.
func (s *PptpService) GeneratePPPOptions(inbound *model.Inbound) error {
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
	b.WriteString("name pptp\n")
	b.WriteString("refuse-pap\n")
	b.WriteString("refuse-chap\n")
	b.WriteString("require-mschap-v2\n")
	// require-mppe-128 (not plain require-mppe): forces 128-bit MPPE so the
	// server offers the S bit; plain require-mppe would accept weak 40-bit.
	b.WriteString("require-mppe-128\n")
	// Disable IPv6CP: the PPTP data path (nftables TPROXY -> Xray) is IPv4-only,
	// so a negotiated IPv6 link would leak IPv6 traffic and DNS past Xray.
	b.WriteString("noipv6\n")
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns1))
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns2))
	b.WriteString("proxyarp\n")
	b.WriteString("nodefaultroute\n")
	b.WriteString("lock\n")
	b.WriteString("nologfd\n")
	b.WriteString("lcp-echo-interval 30\n")
	b.WriteString("lcp-echo-failure 4\n")
	b.WriteString(fmt.Sprintf("mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("mru %d\n", mtu))
	b.WriteString("plugin radius.so\n")
	b.WriteString("radius-config-file /etc/ppp/radius/pptp.conf\n")

	return s.writeFile("/etc/ppp/pptpd-options", b.String())
}

// getDisabledEmails returns a set of client emails that are disabled in the
// client_traffics table (due to traffic limit or expiry).
func (s *PptpService) getDisabledEmails() map[string]bool {
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

// SetupAllTproxy sets up kernel modules, ip rules, and nftables rules for TPROXY.
func (s *PptpService) SetupAllTproxy() error {
	// Enable IP forwarding
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Load kernel modules needed for PPTP
	s.runCmd("modprobe", "nf_conntrack_pptp")
	s.runCmd("modprobe", "ip_gre")
	s.runCmd("modprobe", "ppp_generic")
	s.runCmd("modprobe", "ppp_mppe")
	s.runCmd("modprobe", "nf_tproxy_ipv4")

	// Set up ip rule and route table (check if already exists to avoid duplicates)
	output, _ := exec.Command("ip", "rule", "show").Output()
	if !strings.Contains(string(output), "fwmark 0x1 lookup 100") {
		s.runCmd("ip", "rule", "add", "fwmark", "1", "lookup", "100")
	}
	s.runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	return s.nftService.ApplyNftRules()
}

// RestartServices (re)launches pptpd as a panel-managed child process.
func (s *PptpService) RestartServices() error {
	migrateFromSystemd()

	inbounds, err := s.GetPptpInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		procMgr.Stop("pptpd")
		return nil
	}

	// pptpd --fg runs in the foreground reading /etc/pptpd.conf; the panel
	// supervises it and reaps its pppd children.
	linkPptpCtrl()
	if err := procMgr.Start("pptpd", daemonBin("pptpd"), pptpdArgs(), pppdEnv(), ""); err != nil {
		logger.Warning("PPTP: failed to start pptpd:", err)
	}

	return nil
}

// StopServices stops the PPTP (pptpd) child process.
func (s *PptpService) StopServices() {
	procMgr.Stop("pptpd")
}

// InitPptp initializes PPTP services on panel startup.
func (s *PptpService) InitPptp() {
	inbounds, err := s.GetPptpInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	logger.Info("PPTP: initializing PPTP services for", len(inbounds), "inbound(s)")

	s.nftService.CleanupLegacyIptables()

	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("PPTP: failed to generate configs:", err)
		return
	}
	if err := s.SetupAllTproxy(); err != nil {
		logger.Warning("PPTP: failed to setup TPROXY:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("PPTP: failed to restart services:", err)
	}
}

// KillDisabledSessions kills active PPP sessions for clients that are no longer
// allowed to connect (disabled in settings or disabled in client_traffics).
// Uses RADIUS session data to find active sessions.
func (s *PptpService) KillDisabledSessions() {
	inbounds, err := s.GetPptpInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

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

	if len(disabled) > 0 && s.radiusService != nil {
		s.radiusService.KillSessionsByEmail(disabled)
	}
}

// DisableClients enforces limits for the given client emails by killing their active PPP sessions.
// RADIUS handles auth live from the database, so no config regeneration is needed.
func (s *PptpService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}

	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	if s.radiusService != nil {
		s.radiusService.KillSessionsByEmail(emailSet)
	}
}

func (s *PptpService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0644)
}

func (s *PptpService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *PptpService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("PPTP: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
