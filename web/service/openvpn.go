package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// OpenVpnService manages OpenVPN server configuration including cert generation,
// config files, service management, and client .ovpn downloads.
type OpenVpnService struct {
	inboundService InboundService
	nftService     NftService
	radiusService  *RadiusService
	radiusSecret   string
}

// openvpnSettings represents the OpenVPN-specific settings stored in the inbound's Settings JSON.
type openvpnSettings struct {
	UdpEnable      *bool               `json:"udpEnable"` // nil == enabled (back-compat with pre-toggle inbounds)
	TcpEnable      *bool               `json:"tcpEnable"` // nil == enabled
	TcpPort        int                 `json:"tcpPort"`
	Dns1           string              `json:"dns1"`
	Dns2           string              `json:"dns2"`
	Mtu            int                 `json:"mtu"`
	CaCert         string              `json:"caCert"`
	CaKey          string              `json:"caKey"`
	ServerCert     string              `json:"serverCert"`
	ServerKey      string              `json:"serverKey"`
	TlsCrypt       string              `json:"tlsCrypt"`
	CipherMode     string              `json:"cipherMode"` // old | new | all | custom (informative; Ciphers is authoritative)
	Ciphers        []string            `json:"ciphers"`
	ExternalProxy  []ovpnExternalProxy `json:"externalProxy"`
	ClientToClient bool                `json:"clientToClient"`
	CrossInbound   bool                `json:"crossInbound"`
	UserLimit         int              `json:"userLimit"`         // simultaneous devices per account (1..64); 1 = legacy
	UserLimitStrategy string           `json:"userLimitStrategy"` // at the cap: "reject" (default) or "accept" (evict oldest)
	IpRanges       []string            `json:"ipRanges"`  // UDP-side /24 ranges; TCP mirrors into 10.3.x. Panel-managed.
	Clients        []openvpnClient     `json:"clients"`
}

// effectiveRanges returns the inbound's UDP-side (10.2.x) client ranges, or nil
// to signal the legacy id-derived /24.
func (o *openvpnSettings) effectiveRanges() []string { return o.IpRanges }

// ovpnExternalProxy is one `remote` override for exported client configs —
// e.g. a relay/CDN address handed to clients instead of this server's IP.
type ovpnExternalProxy struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// ovpnDefaultCiphers matches the historical hardcoded negotiation list and the
// frontend's "New Devices" preset.
var ovpnDefaultCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

// ovpnLegacyProviderCiphers are ciphers OpenSSL 3 only exposes via the legacy
// provider; selecting any of them requires `providers legacy default`.
// (DES-EDE3-CBC lives in the default provider and is deliberately absent.)
var ovpnLegacyProviderCiphers = map[string]bool{
	"BF-CBC":      true,
	"CAST5-CBC":   true,
	"SEED-CBC":    true,
	"DES-CBC":     true,
	"DES-EDE-CBC": true,
	"RC2-CBC":     true,
	"RC2-64-CBC":  true,
	"RC2-40-CBC":  true,
}

// dataCiphers returns the configured cipher preference list, falling back to
// the defaults when the inbound predates cipher selection.
func (o *openvpnSettings) dataCiphers() []string {
	ciphers := make([]string, 0, len(o.Ciphers))
	for _, c := range o.Ciphers {
		if c = strings.TrimSpace(c); c != "" {
			ciphers = append(ciphers, c)
		}
	}
	if len(ciphers) == 0 {
		return ovpnDefaultCiphers
	}
	return ciphers
}

// firstCbcCipher returns the highest-preference CBC cipher, or "" if the list
// is AEAD-only. Used as the non-NCP fallback for old clients.
func firstCbcCipher(ciphers []string) string {
	for _, c := range ciphers {
		if strings.HasSuffix(c, "-CBC") {
			return c
		}
	}
	return ""
}

func needsLegacyProvider(ciphers []string) bool {
	for _, c := range ciphers {
		if ovpnLegacyProviderCiphers[c] {
			return true
		}
	}
	return false
}

// Cipher support is probed once from the actual openvpn binary. The bundled
// static (musl) build ships an OpenSSL that CANNOT dlopen the legacy provider
// (`legacy.so: Dynamic loading not supported`), so BF-CBC/CAST5/SEED/DES/RC2 are
// unavailable and `providers legacy default` is fatal — while a distro openvpn
// (dynamic OpenSSL) can load it. We therefore ask the binary what it actually
// supports instead of assuming.
var (
	ovpnCipherProbeOnce sync.Once
	ovpnSupportedCipher map[string]bool
	ovpnLegacyProvider  bool
)

// ovpnBinaryPath returns the openvpn executable the panel runs: the bundled
// daemon if extracted, else a distro openvpn from PATH.
func (s *OpenVpnService) ovpnBinaryPath() string {
	return daemonBin("openvpn")
}

var (
	ovpnDcoProbeOnce sync.Once
	ovpnHasDco       bool
)

// hasDCO reports whether the openvpn build has Data Channel Offload compiled in
// (the [DCO] flag in --version). It matters for client-to-client: with DCO
// active OpenVPN ignores `client-to-client` and pushes packets to the tun
// device (where TPROXY hijacks them), so the panel disables DCO in that case.
func (s *OpenVpnService) hasDCO() bool {
	ovpnDcoProbeOnce.Do(func() {
		out, _ := exec.Command(s.ovpnBinaryPath(), "--version").CombinedOutput()
		ovpnHasDco = strings.Contains(string(out), "[DCO]")
	})
	return ovpnHasDco
}

// parseOvpnCiphers adds every cipher token from `openvpn --show-ciphers` output
// to set. Cipher lines start with an all-uppercase dashed token (AES-256-GCM,
// CHACHA20-POLY1305, DES-EDE3-CBC); prose/header lines contain lowercase and are
// skipped.
func parseOvpnCiphers(output string, set map[string]bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !strings.Contains(name, "-") || strings.ToUpper(name) != name {
			continue
		}
		set[name] = true
	}
}

// cipherSupport reports the data ciphers the openvpn binary can actually
// negotiate, and whether the OpenSSL legacy provider loads. Cached — it shells
// out to the binary.
func (s *OpenVpnService) cipherSupport() (map[string]bool, bool) {
	ovpnCipherProbeOnce.Do(func() {
		set := map[string]bool{}
		bin := s.ovpnBinaryPath()
		if out, err := exec.Command(bin, "--show-ciphers").CombinedOutput(); err == nil {
			parseOvpnCiphers(string(out), set)
		}
		// The legacy provider only counts if it loads AND contributes ciphers.
		if out, err := exec.Command(bin, "--providers", "legacy", "default", "--show-ciphers").CombinedOutput(); err == nil &&
			!strings.Contains(string(out), "failed to load provider") {
			before := len(set)
			parseOvpnCiphers(string(out), set)
			if len(set) > before {
				ovpnLegacyProvider = true
			}
		}
		ovpnSupportedCipher = set
	})
	return ovpnSupportedCipher, ovpnLegacyProvider
}

// effectiveCiphers filters the configured preference list down to what the
// openvpn binary supports, so a cipher the local build can't provide never
// reaches a config file (which would make openvpn refuse to start / a client
// reject the profile). Falls back to the always-present AEAD defaults if the
// filter empties the list, and to the raw list if the probe was unavailable.
func (s *OpenVpnService) effectiveCiphers(configured []string) []string {
	supported, _ := s.cipherSupport()
	if len(supported) == 0 {
		return configured
	}
	out := make([]string, 0, len(configured))
	for _, c := range configured {
		if supported[strings.ToUpper(c)] {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return ovpnDefaultCiphers
	}
	return out
}

// udpEnabled / tcpEnabled report whether a transport is active. A nil pointer
// (older inbound saved before the toggles existed) is treated as enabled so we
// never silently take a working server offline on upgrade.
func (o *openvpnSettings) udpEnabled() bool { return o.UdpEnable == nil || *o.UdpEnable }
func (o *openvpnSettings) tcpEnabled() bool { return o.TcpEnable == nil || *o.TcpEnable }

// tcpPortOrDefault returns the configured TCP port, defaulting to 443.
func (o *openvpnSettings) tcpPortOrDefault() int {
	if o.TcpPort == 0 {
		return 443
	}
	return o.TcpPort
}

type openvpnClient struct {
	ID       string `json:"id"`       // OpenVPN username
	Password string `json:"password"` // OpenVPN password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius configures the RADIUS service and shared secret for OpenVPN authentication.
func (s *OpenVpnService) SetRadius(rs *RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

func (s *OpenVpnService) GetOpenVpnInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "openvpn").Find(&inbounds).Error
	return inbounds, err
}

func (s *OpenVpnService) parseSettings(inbound *model.Inbound) (*openvpnSettings, error) {
	settings := &openvpnSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// configDir returns the directory for an OpenVPN inbound's config/cert files.
func (s *OpenVpnService) configDir(inboundId int) string {
	return fmt.Sprintf("/etc/openvpn/server-%d", inboundId)
}

// ovpnBlockFor returns the network address and prefix length of an OpenVPN
// inbound's transport block, derived from its stored ranges. Clients live inside
// this block; the server takes its .1. Defaults to the legacy 10.{2|3}.{id}.0/24
// when no ranges are stored, so <=253-client inbounds are byte-identical to the
// pre-multi-range behavior.
func ovpnBlockFor(inbound *model.Inbound, settings *openvpnSettings, proto string) (net.IP, int) {
	return ovpnBlock(settings.effectiveRanges(), proto, inbound.Id)
}

// ovpnClientIP returns the deterministic tunnel IP (pinned via client-config-dir)
// for the client at index i on the given transport. Returns "" when the index
// overflows the inbound's block.
func ovpnClientIP(inbound *model.Inbound, settings *openvpnSettings, i int, proto string) string {
	netAddr, prefix := ovpnBlockFor(inbound, settings, proto)
	return ovpnBlockClientIP(netAddr, prefix, i)
}

// binaryPath returns the absolute path of the running panel binary, used for
// OpenVPN's hook scripts (auth-user-pass-verify / client-connect / -disconnect).
// It resolves the real executable so the config never points at a stale symlink
// or a wrong distro-specific path. Falls back to the historical fixed path only
// if the executable can't be determined.
func (s *OpenVpnService) binaryPath() string {
	if exe, err := os.Executable(); err == nil {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			return resolved
		}
		return exe
	}
	return "/usr/local/vpn-ui/vpn-ui"
}

// GetTproxyPort returns a deterministic TPROXY/dokodemo port for the given
// inbound. Inbound IDs are globally unique, so this shares L2TP/PPTP's 12300+id
// formula without colliding with them.
func (s *OpenVpnService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound that captures the
// TPROXY-redirected OpenVPN traffic and feeds it into Xray's routing — the same
// mechanism L2TP/PPTP use so OpenVPN clients obey the panel's outbound rules.
func (s *OpenVpnService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
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

// InitOpenVpn initializes OpenVPN services on panel startup.
func (s *OpenVpnService) InitOpenVpn() {
	inbounds, err := s.GetOpenVpnInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	logger.Info("OpenVPN: initializing services for", len(inbounds), "inbound(s)")

	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("OpenVPN: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("OpenVPN: failed to setup routing:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("OpenVPN: failed to restart services:", err)
	}
}

// GenerateAllConfigs regenerates all OpenVPN-related config files from the database state.
func (s *OpenVpnService) GenerateAllConfigs() error {
	inbounds, err := s.GetOpenVpnInbounds()
	if err != nil {
		return err
	}
	if len(inbounds) == 0 {
		return nil
	}

	for _, inbound := range inbounds {
		if err := s.generateServerConfigs(inbound); err != nil {
			logger.Warning("OpenVPN: skipping inbound", inbound.Id, err)
			continue
		}
		if err := s.writeCertFiles(inbound); err != nil {
			logger.Warning("OpenVPN: cert write failed for inbound", inbound.Id, err)
		}
	}

	return nil
}

// generateServerConfigs writes the UDP and TCP server config files for an OpenVPN inbound.
func (s *OpenVpnService) generateServerConfigs(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}

	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)
	os.MkdirAll("/var/run/openvpn", 0755)
	os.MkdirAll("/etc/openvpn/server", 0755)

	// Path to the running panel binary, used as OpenVPN's auth/connect/disconnect
	// hook. Resolved at runtime — the install location varies by distro
	// (/root/vpn-ui, /usr/local/vpn-ui/vpn-ui, /usr/lib/vpn-ui/vpn-ui, …) and a wrong
	// path makes OpenVPN refuse to start (auth-user-pass-verify script not found).
	binaryPath := s.binaryPath()

	ports := map[string]int{
		"udp": inbound.Port,
		"tcp": settings.tcpPortOrDefault(),
	}
	enabled := map[string]bool{
		"udp": settings.udpEnabled(),
		"tcp": settings.tcpEnabled(),
	}

	for _, proto := range []string{"udp", "tcp"} {
		if !enabled[proto] {
			continue
		}
		confPath := fmt.Sprintf("%s/server-%s.conf", dir, proto)
		conf := s.buildServerConfig(inbound, settings, proto, ports[proto], binaryPath)
		if err := s.writeFile(confPath, conf); err != nil {
			return err
		}
		if err := s.writeClientConfigDir(inbound, settings, proto); err != nil {
			logger.Warning("OpenVPN: CCD write failed for inbound", inbound.Id, err)
		}
	}

	return nil
}

// ovpnProcName returns the process-manager key for an OpenVPN inbound/transport.
func ovpnProcName(inboundId int, proto string) string {
	return fmt.Sprintf("openvpn-server-%d-%s", inboundId, proto)
}

// writeClientConfigDir writes the per-client client-config-dir files that pin
// each user to a deterministic tunnel IP (ifconfig-push). Deterministic IPs are
// what let the panel translate per-user routing rules (matched by email) into
// source-IP rules the dokodemo-door path can match — the same trick L2TP/PPTP
// use. Lookups are keyed by common-name, which username-as-common-name sets to
// the authenticated username (client.ID).
func (s *OpenVpnService) writeClientConfigDir(inbound *model.Inbound, settings *openvpnSettings, proto string) error {
	ccdDir := fmt.Sprintf("%s/ccd-%s", s.configDir(inbound.Id), proto)
	// Rebuild from scratch so deleted/renamed users don't leave stale pins.
	os.RemoveAll(ccdDir)
	if err := os.MkdirAll(ccdDir, 0755); err != nil {
		return err
	}
	netAddr, prefix := ovpnBlockFor(inbound, settings, proto)
	mask := prefixToMask(prefix)
	k := normUserLimit(settings.UserLimit)

	// User Limit K>=2: no fixed per-CN pin. Instead publish each account's aligned
	// block to blocks-<proto>/<CN>; the client-connect hook leases a free IP inside
	// it per device (duplicate-cn allows K simultaneous sessions on one account).
	blocksDir := fmt.Sprintf("%s/blocks-%s", s.configDir(inbound.Id), proto)
	os.RemoveAll(blocksDir)
	if k > 1 {
		if err := os.MkdirAll(blocksDir, 0755); err != nil {
			return err
		}
		// Fresh lease dir on every (re)gen — a config change restarts the daemon,
		// dropping all sessions, so no live lease can be lost here.
		leaseDir := fmt.Sprintf("%s/leases-%s", s.configDir(inbound.Id), proto)
		os.RemoveAll(leaseDir)
		_ = os.MkdirAll(leaseDir, 0755)

		// Publish the User Limit Strategy for the connect hook: "reject" refuses a
		// (K+1)-th device; "accept" evicts the account's oldest device via the mgmt
		// socket. One file per proto so udp/tcp share the inbound's setting.
		strategy := normUserLimitStrategy(settings.UserLimitStrategy)
		if err := s.writeFile(fmt.Sprintf("%s/strategy-%s", s.configDir(inbound.Id), proto), strategy+"\n"); err != nil {
			return err
		}

		subnets := ovpnSubnetsOrDefault(settings, proto, inbound.Id)
		for i, client := range settings.Clients {
			if client.ID == "" {
				continue
			}
			ips := vpnAccountDeviceIPs(subnets, i, k)
			if len(ips) == 0 {
				continue
			}
			// "<serverBlockMask> <ip1> <ip2> ...": the hook leases a free IP from the
			// list and pushes ifconfig-push <freeIP> <serverBlockMask> (topology
			// subnet). An explicit IP list, so K need not be a power of two.
			content := mask + " " + strings.Join(ips, " ") + "\n"
			if err := s.writeFile(fmt.Sprintf("%s/%s", blocksDir, client.ID), content); err != nil {
				return err
			}
		}
		return nil
	}

	// K==1 (legacy): pin each account to one deterministic IP via CCD.
	for i, client := range settings.Clients {
		if client.ID == "" {
			continue
		}
		ip := ovpnBlockClientIP(netAddr, prefix, i)
		if ip == "" {
			continue
		}
		content := fmt.Sprintf("ifconfig-push %s %s\n", ip, mask)
		if err := s.writeFile(fmt.Sprintf("%s/%s", ccdDir, client.ID), content); err != nil {
			return err
		}
	}
	return nil
}

// buildServerConfig returns the OpenVPN server config content for a given protocol.
func (s *OpenVpnService) buildServerConfig(inbound *model.Inbound, settings *openvpnSettings, proto string, port int, binaryPath string) string {
	id := inbound.Id
	dir := s.configDir(id)

	// Client subnet/block for this transport (UDP => 10.2.x, TCP => 10.3.x).
	// A single /24 for the common case; a wider aligned block once an inbound
	// has grown past 253 clients (see normalizeOvpnRanges).
	netAddr, prefix := ovpnBlockFor(inbound, settings, proto)
	subnet := netAddr.String()
	subnetMask := prefixToMask(prefix)

	protoStr := proto
	if proto == "tcp" {
		protoStr = "tcp-server"
	}

	dns1 := settings.Dns1
	if dns1 == "" {
		dns1 = "8.8.8.8"
	}
	dns2 := settings.Dns2
	if dns2 == "" {
		dns2 = "8.8.4.4"
	}
	mtu := settings.Mtu
	if mtu == 0 {
		mtu = 1500
	}

	tunDev := fmt.Sprintf("tun-ovpn-%d-%s", id, proto[:1])

	explicitExitNotify := "1"
	if proto == "tcp" {
		explicitExitNotify = "0"
	}

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui OpenVPN service\n")
	b.WriteString(fmt.Sprintf("port %d\n", port))
	b.WriteString(fmt.Sprintf("proto %s\n", protoStr))
	b.WriteString(fmt.Sprintf("dev %s\n", tunDev))
	b.WriteString("dev-type tun\n")
	b.WriteString("topology subnet\n")
	b.WriteString(fmt.Sprintf("server %s %s\n", subnet, subnetMask))
	// Pin every user to a deterministic tunnel IP so per-user routing rules work.
	b.WriteString(fmt.Sprintf("client-config-dir %s/ccd-%s\n", dir, proto))
	// User Limit K>=2: allow K simultaneous sessions per account (same CN). The
	// client-connect hook leases each device a distinct IP inside the account's
	// block, so routing-by-source still resolves to the right account.
	if normUserLimit(settings.UserLimit) > 1 {
		b.WriteString("duplicate-cn\n")
		// The "accept" strategy force-disconnects the account's oldest device via
		// `client-kill <CID>` on the management socket — which is already declared
		// unconditionally below (status/management block), so nothing to add here.
	}
	if settings.ClientToClient {
		// Route traffic between clients internally in OpenVPN instead of sending
		// it to the tun device (where TPROXY would hijack it into Xray). DCO
		// ignores client-to-client, so turn it off when the build has it.
		if s.hasDCO() {
			b.WriteString("disable-dco\n")
		}
		b.WriteString("client-to-client\n")
	}
	b.WriteString("push \"redirect-gateway def1 bypass-dhcp\"\n")
	b.WriteString(fmt.Sprintf("push \"dhcp-option DNS %s\"\n", dns1))
	b.WriteString(fmt.Sprintf("push \"dhcp-option DNS %s\"\n", dns2))
	// The VPN data path (nftables TPROXY -> Xray) is IPv4-only. Block IPv6 on the
	// client so a dual-stack host can't leak IPv6 traffic/DNS out its own default
	// route, bypassing Xray entirely (mirrors the L2TP/PPTP noipv6 fix).
	b.WriteString("push \"block-ipv6\"\n")
	b.WriteString(fmt.Sprintf("tun-mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("ca %s/ca.crt\n", dir))
	b.WriteString(fmt.Sprintf("cert %s/server.crt\n", dir))
	b.WriteString(fmt.Sprintf("key %s/server.key\n", dir))
	b.WriteString(fmt.Sprintf("tls-crypt %s/tc.key\n", dir))
	b.WriteString("dh none\n")
	ciphers := s.effectiveCiphers(settings.dataCiphers())
	_, legacyOK := s.cipherSupport()
	if legacyOK && needsLegacyProvider(ciphers) {
		b.WriteString("providers legacy default\n")
	}
	b.WriteString(fmt.Sprintf("data-ciphers %s\n", strings.Join(ciphers, ":")))
	if cbc := firstCbcCipher(ciphers); cbc != "" {
		// Old clients (no cipher negotiation) end up on the preferred CBC cipher.
		b.WriteString(fmt.Sprintf("data-ciphers-fallback %s\n", cbc))
	}
	b.WriteString(fmt.Sprintf("cipher %s\n", ciphers[0]))
	b.WriteString("auth SHA256\n")
	b.WriteString("verify-client-cert none\n")
	b.WriteString("username-as-common-name\n")
	b.WriteString("script-security 3\n")
	b.WriteString(fmt.Sprintf("auth-user-pass-verify \"%s openvpn-auth %d\" via-file\n", binaryPath, id))
	b.WriteString(fmt.Sprintf("client-connect \"%s openvpn-connect %d\"\n", binaryPath, id))
	b.WriteString(fmt.Sprintf("client-disconnect \"%s openvpn-disconnect %d\"\n", binaryPath, id))
	b.WriteString("keepalive 10 120\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString(fmt.Sprintf("status /var/run/openvpn/status-%d-%s.log 5\n", id, proto))
	b.WriteString("status-version 3\n")
	b.WriteString(fmt.Sprintf("management /var/run/openvpn/mgmt-%d-%s.sock unix\n", id, proto))
	b.WriteString("verb 3\n")
	b.WriteString(fmt.Sprintf("explicit-exit-notify %s\n", explicitExitNotify))

	return b.String()
}

// writeCertFiles writes CA, server cert/key, and tls-crypt key to disk.
func (s *OpenVpnService) writeCertFiles(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}

	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)

	if settings.CaCert != "" {
		if err := s.writeFile(dir+"/ca.crt", settings.CaCert); err != nil {
			return err
		}
	}
	if settings.CaKey != "" {
		if err := s.writeFileMode(dir+"/ca.key", settings.CaKey, 0600); err != nil {
			return err
		}
	}
	if settings.ServerCert != "" {
		if err := s.writeFile(dir+"/server.crt", settings.ServerCert); err != nil {
			return err
		}
	}
	if settings.ServerKey != "" {
		if err := s.writeFileMode(dir+"/server.key", settings.ServerKey, 0600); err != nil {
			return err
		}
	}
	if settings.TlsCrypt != "" {
		if err := s.writeFileMode(dir+"/tc.key", settings.TlsCrypt, 0600); err != nil {
			return err
		}
	}

	return nil
}

// SetupRouting prepares the host so OpenVPN client traffic is TPROXY-redirected
// into Xray instead of NAT'd straight to the internet: it enables forwarding,
// loads the tproxy/tun modules, installs the fwmark policy route, and reapplies
// the nftables rules. Mirrors L2tpService.SetupAllTproxy.
func (s *OpenVpnService) SetupRouting() error {
	// Enable IP forwarding
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Kernel modules for the tun device + TPROXY redirect.
	s.runCmd("modprobe", "tun")
	s.runCmd("modprobe", "nf_tproxy_ipv4")

	// Deliver fwmark-1 packets locally so TPROXY can hand them to the dokodemo
	// socket (shared table 100 with L2TP/PPTP; add/replace are idempotent).
	output, _ := exec.Command("ip", "rule", "show").Output()
	if !strings.Contains(string(output), "fwmark 0x1 lookup 100") {
		s.runCmd("ip", "rule", "add", "fwmark", "1", "lookup", "100")
	}
	s.runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	return s.nftService.ApplyNftRules()
}

// RestartServices launches (or stops) an OpenVPN child process per inbound and
// transport, according to the enable toggles. Any managed OpenVPN process that
// no longer corresponds to an enabled transport (disabled toggle, disabled or
// deleted inbound) is stopped, so nothing lingers.
func (s *OpenVpnService) RestartServices() error {
	migrateFromSystemd()

	inbounds, err := s.GetOpenVpnInbounds()
	if err != nil {
		return err
	}

	bin := s.ovpnBinaryPath()
	desired := map[string]bool{}

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("OpenVPN: skipping inbound", inbound.Id, err)
			continue
		}
		dir := s.configDir(inbound.Id)
		for _, proto := range []string{"udp", "tcp"} {
			on := inbound.Enable && (proto == "udp" && settings.udpEnabled() || proto == "tcp" && settings.tcpEnabled())
			name := ovpnProcName(inbound.Id, proto)
			if !on {
				continue
			}
			desired[name] = true
			confPath := fmt.Sprintf("%s/server-%s.conf", dir, proto)
			args := []string{"--suppress-timestamps", "--config", confPath}
			if err := procMgr.Start(name, bin, args, nil, dir); err != nil {
				logger.Warning("OpenVPN: failed to start", name, err)
			}
		}
	}

	// Stop every managed OpenVPN process that shouldn't be running anymore.
	for _, name := range procMgr.namesWithPrefix("openvpn-server-") {
		if !desired[name] {
			_ = procMgr.Stop(name)
		}
	}

	return nil
}

// StopServices stops all OpenVPN child processes.
func (s *OpenVpnService) StopServices() {
	procMgr.StopByPrefix("openvpn-server-")
}

// GenerateClientConfig builds the .ovpn client config content for an inbound/protocol.
func (s *OpenVpnService) GenerateClientConfig(inbound *model.Inbound, proto string) (string, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return "", err
	}

	if settings.CaCert == "" || settings.TlsCrypt == "" {
		return "", fmt.Errorf("certificates not generated yet — use 'Generate Self-Signed CA' first")
	}

	// Refuse to hand out a profile for a transport the admin has switched off.
	if proto == "tcp" && !settings.tcpEnabled() {
		return "", fmt.Errorf("TCP transport is disabled for this inbound")
	}
	if proto == "udp" && !settings.udpEnabled() {
		return "", fmt.Errorf("UDP transport is disabled for this inbound")
	}

	port := inbound.Port
	protoStr := "udp"
	if proto == "tcp" {
		port = settings.tcpPortOrDefault()
		protoStr = "tcp"
	}

	// External proxy entries override the auto-detected server address; each
	// becomes a `remote` line (OpenVPN tries them in order). An entry without a
	// port inherits the transport's real port.
	type remote struct {
		host string
		port int
	}
	var remotes []remote
	for _, ep := range settings.ExternalProxy {
		dest := strings.TrimSpace(ep.Dest)
		if dest == "" {
			continue
		}
		epPort := ep.Port
		if epPort == 0 {
			epPort = port
		}
		remotes = append(remotes, remote{dest, epPort})
	}
	if len(remotes) == 0 {
		serverIP := s.getServerIP()
		if serverIP == "" {
			return "", fmt.Errorf("could not determine server IP")
		}
		remotes = append(remotes, remote{serverIP, port})
	}

	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString(fmt.Sprintf("proto %s\n", protoStr))
	for _, r := range remotes {
		b.WriteString(fmt.Sprintf("remote %s %d\n", r.host, r.port))
	}
	b.WriteString("resolv-retry infinite\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	if proto == "udp" {
		// Notify the server on clean exit (SIGTERM) so it frees the client's slot
		// immediately instead of waiting out the keepalive timeout — important for
		// the per-account User Limit, where the freed IP should be reusable right
		// away. UDP only; a TCP disconnect is seen by the server as a socket close.
		b.WriteString("explicit-exit-notify 3\n")
	}
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("auth-user-pass\n")
	// This profile authenticates by username/password only and carries no
	// <cert>/<key> (the server runs `verify-client-cert none`). OpenVPN Connect
	// (openvpn3) otherwise rejects such a profile with "missing external
	// certificate"; this directive tells it no client certificate is expected.
	// The community CLI just treats it as a harmless env var.
	b.WriteString("setenv CLIENT_CERT 0\n")
	ciphers := s.effectiveCiphers(settings.dataCiphers())
	_, legacyOK := s.cipherSupport()
	joined := strings.Join(ciphers, ":")
	if legacyOK && needsLegacyProvider(ciphers) {
		// 2.6+ clients must load the OpenSSL legacy provider or they reject the
		// data-ciphers list outright; `setenv opt` keeps the line ignorable on
		// pre-2.6 clients that don't know --providers (their OpenSSL 1.x has
		// these ciphers built in). Only emitted when this server's own openvpn
		// can load the provider — otherwise the legacy ciphers were already
		// filtered out of `ciphers` and the line would be dead weight.
		b.WriteString("setenv opt providers legacy default\n")
	}
	if cbc := firstCbcCipher(ciphers); cbc != "" {
		// `setenv opt` keeps the profile loadable on pre-2.5 clients that don't
		// know data-ciphers; they fall back to the plain `cipher` line, which the
		// server accepts via data-ciphers-fallback.
		b.WriteString(fmt.Sprintf("setenv opt data-ciphers %s\n", joined))
		b.WriteString(fmt.Sprintf("cipher %s\n", cbc))
	} else {
		b.WriteString(fmt.Sprintf("data-ciphers %s\n", joined))
		b.WriteString(fmt.Sprintf("cipher %s\n", ciphers[0]))
	}
	b.WriteString("auth SHA256\n")
	b.WriteString("verb 3\n")
	b.WriteString("<ca>\n")
	b.WriteString(strings.TrimSpace(settings.CaCert))
	b.WriteString("\n</ca>\n")
	b.WriteString("<tls-crypt>\n")
	b.WriteString(strings.TrimSpace(settings.TlsCrypt))
	b.WriteString("\n</tls-crypt>\n")

	return b.String(), nil
}

// GenerateSelfSignedCA generates a self-signed CA, server certificate, and tls-crypt key.
// Returns PEM-encoded strings: caCert, caKey, serverCert, serverKey, tlsCrypt.
func (s *OpenVpnService) GenerateSelfSignedCA() (string, string, string, string, string, error) {
	// Generate CA key
	caPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to generate CA key: %w", err)
	}

	// CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"vpn-ui"},
			CommonName:   "vpn-ui OpenVPN CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to create CA cert: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caKeyDER, _ := x509.MarshalECPrivateKey(caPriv)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

	// Parse CA cert for signing server cert
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Generate server key
	serverPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to generate server key: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"vpn-ui"},
			CommonName:   "vpn-ui OpenVPN Server",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to create server cert: %w", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverPriv)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	// Generate tls-crypt key (OpenVPN static key v1 format — 256 bytes random)
	tlsCryptKey, err := s.generateTlsCryptKey()
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to generate tls-crypt key: %w", err)
	}

	return string(caCertPEM), string(caKeyPEM), string(serverCertPEM), string(serverKeyPEM), tlsCryptKey, nil
}

// generateTlsCryptKey generates an OpenVPN tls-crypt static key (v1 format).
func (s *OpenVpnService) generateTlsCryptKey() (string, error) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n")
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(key); i += 16 {
		end := i + 16
		if end > len(key) {
			end = len(key)
		}
		b.WriteString(fmt.Sprintf("%x\n", key[i:end]))
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")

	return b.String(), nil
}

// KillClient kills a specific client's connection via the management socket.
func (s *OpenVpnService) KillClient(inboundId int, username string) {
	// Try both UDP and TCP management sockets
	for _, proto := range []string{"udp", "tcp"} {
		sockPath := fmt.Sprintf("/var/run/openvpn/mgmt-%d-%s.sock", inboundId, proto)
		s.killClientViaMgmt(sockPath, username)
	}
}

// killClientViaMgmt sends a kill command to the OpenVPN management interface.
func (s *OpenVpnService) killClientViaMgmt(sockPath, username string) {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Read the greeting
	buf := make([]byte, 1024)
	conn.Read(buf)
	// Send kill command
	fmt.Fprintf(conn, "kill %s\n", username)
	conn.Read(buf)
}

// KillDisabledSessions kills active OpenVPN sessions for clients that are disabled.
func (s *OpenVpnService) KillDisabledSessions() {
	inbounds, err := s.GetOpenVpnInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// DisableClients enforces limits for the given client emails by killing their active sessions.
func (s *OpenVpnService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}

	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	inbounds, err := s.GetOpenVpnInbounds()
	if err != nil {
		return
	}

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if emailSet[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// getDisabledEmails returns a set of client emails that are disabled in the
// client_traffics table (due to traffic limit or expiry).
func (s *OpenVpnService) getDisabledEmails() map[string]bool {
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

// getServerIP returns the server's public IP address.
func (s *OpenVpnService) getServerIP() string {
	// Try to get the default route interface IP
	output, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err == nil {
		parts := strings.Fields(string(output))
		for i, p := range parts {
			if p == "src" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (s *OpenVpnService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0644)
}

func (s *OpenVpnService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *OpenVpnService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("OpenVPN: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
