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
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// OpenVpnService manages OpenVPN server configuration including cert generation,
// config files, service management, and client .ovpn downloads.
type OpenVpnService struct {
	inboundService InboundService
	nftService     NftService
	radiusService  RadiusService
	radiusSecret   string
}

// openvpnSettings represents the OpenVPN-specific settings stored in the inbound's Settings JSON.
type openvpnSettings struct {
	TcpPort    int            `json:"tcpPort"`
	Dns1       string         `json:"dns1"`
	Dns2       string         `json:"dns2"`
	Mtu        int            `json:"mtu"`
	CaCert     string         `json:"caCert"`
	CaKey      string         `json:"caKey"`
	ServerCert string         `json:"serverCert"`
	ServerKey  string         `json:"serverKey"`
	TlsCrypt   string         `json:"tlsCrypt"`
	Clients    []openvpnClient `json:"clients"`
}

type openvpnClient struct {
	ID       string `json:"id"`       // OpenVPN username
	Password string `json:"password"` // OpenVPN password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius configures the RADIUS service and shared secret for OpenVPN authentication.
func (s *OpenVpnService) SetRadius(rs RadiusService, secret string) {
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
	if err := s.SetupNAT(); err != nil {
		logger.Warning("OpenVPN: failed to setup NAT:", err)
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

	// Get the x-ui binary path for hook scripts
	binaryPath := "/usr/local/x-ui/x-ui"

	// UDP config
	udpConf := s.buildServerConfig(inbound, settings, "udp", inbound.Port, binaryPath)
	if err := s.writeFile(fmt.Sprintf("%s/server-udp.conf", dir), udpConf); err != nil {
		return err
	}

	// TCP config
	tcpPort := settings.TcpPort
	if tcpPort == 0 {
		tcpPort = 443
	}
	tcpConf := s.buildServerConfig(inbound, settings, "tcp", tcpPort, binaryPath)
	if err := s.writeFile(fmt.Sprintf("%s/server-tcp.conf", dir), tcpConf); err != nil {
		return err
	}

	// Create symlinks for systemd
	s.runCmd("ln", "-sf", fmt.Sprintf("%s/server-udp.conf", dir),
		fmt.Sprintf("/etc/openvpn/server/server-%d-udp.conf", inbound.Id))
	s.runCmd("ln", "-sf", fmt.Sprintf("%s/server-tcp.conf", dir),
		fmt.Sprintf("/etc/openvpn/server/server-%d-tcp.conf", inbound.Id))

	return nil
}

// buildServerConfig returns the OpenVPN server config content for a given protocol.
func (s *OpenVpnService) buildServerConfig(inbound *model.Inbound, settings *openvpnSettings, proto string, port int, binaryPath string) string {
	id := inbound.Id
	dir := s.configDir(id)

	// Determine subnet based on protocol
	// UDP: 10.2.{id}.0/24, TCP: 10.3.{id}.0/24
	subnetPrefix := 2
	if proto == "tcp" {
		subnetPrefix = 3
	}
	subnet := fmt.Sprintf("10.%d.%d.0", subnetPrefix, id)

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
	b.WriteString("# Auto-generated by 3x-ui OpenVPN service\n")
	b.WriteString(fmt.Sprintf("port %d\n", port))
	b.WriteString(fmt.Sprintf("proto %s\n", protoStr))
	b.WriteString(fmt.Sprintf("dev %s\n", tunDev))
	b.WriteString("dev-type tun\n")
	b.WriteString("topology subnet\n")
	b.WriteString(fmt.Sprintf("server %s 255.255.255.0\n", subnet))
	b.WriteString("push \"redirect-gateway def1 bypass-dhcp\"\n")
	b.WriteString(fmt.Sprintf("push \"dhcp-option DNS %s\"\n", dns1))
	b.WriteString(fmt.Sprintf("push \"dhcp-option DNS %s\"\n", dns2))
	b.WriteString(fmt.Sprintf("tun-mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("ca %s/ca.crt\n", dir))
	b.WriteString(fmt.Sprintf("cert %s/server.crt\n", dir))
	b.WriteString(fmt.Sprintf("key %s/server.key\n", dir))
	b.WriteString(fmt.Sprintf("tls-crypt %s/tc.key\n", dir))
	b.WriteString("dh none\n")
	b.WriteString("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n")
	b.WriteString("cipher AES-256-GCM\n")
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
	b.WriteString(fmt.Sprintf("status /var/run/openvpn/status-%d-%s.log 10\n", id, proto))
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

// SetupNAT configures IP forwarding and nftables NAT rules for OpenVPN subnets.
func (s *OpenVpnService) SetupNAT() error {
	// Enable IP forwarding
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	return s.nftService.ApplyNftRules()
}

// RestartServices restarts OpenVPN systemd services for all inbounds.
func (s *OpenVpnService) RestartServices() error {
	inbounds, err := s.GetOpenVpnInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		return nil
	}

	os.MkdirAll("/etc/openvpn/server", 0755)

	for _, inbound := range inbounds {
		udpSvc := fmt.Sprintf("openvpn-server@server-%d-udp", inbound.Id)
		tcpSvc := fmt.Sprintf("openvpn-server@server-%d-tcp", inbound.Id)

		if inbound.Enable {
			s.runCmd("systemctl", "enable", "--now", udpSvc)
			s.runCmd("systemctl", "restart", udpSvc)
			s.runCmd("systemctl", "enable", "--now", tcpSvc)
			s.runCmd("systemctl", "restart", tcpSvc)
		} else {
			s.runCmd("systemctl", "stop", udpSvc)
			s.runCmd("systemctl", "disable", udpSvc)
			s.runCmd("systemctl", "stop", tcpSvc)
			s.runCmd("systemctl", "disable", tcpSvc)
		}
	}

	return nil
}

// StopServices stops all OpenVPN systemd services.
func (s *OpenVpnService) StopServices() {
	inbounds, err := s.GetOpenVpnInbounds()
	if err != nil {
		return
	}
	for _, inbound := range inbounds {
		s.runCmd("systemctl", "stop", fmt.Sprintf("openvpn-server@server-%d-udp", inbound.Id))
		s.runCmd("systemctl", "stop", fmt.Sprintf("openvpn-server@server-%d-tcp", inbound.Id))
	}
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

	// Determine server IP
	serverIP := s.getServerIP()
	if serverIP == "" {
		return "", fmt.Errorf("could not determine server IP")
	}

	port := inbound.Port
	protoStr := "udp"
	if proto == "tcp" {
		port = settings.TcpPort
		if port == 0 {
			port = 443
		}
		protoStr = "tcp"
	}

	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString(fmt.Sprintf("proto %s\n", protoStr))
	b.WriteString(fmt.Sprintf("remote %s %d\n", serverIP, port))
	b.WriteString("resolv-retry infinite\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("auth-user-pass\n")
	b.WriteString("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n")
	b.WriteString("cipher AES-256-GCM\n")
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
			Organization: []string{"3x-ui"},
			CommonName:   "3x-ui OpenVPN CA",
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
			Organization: []string{"3x-ui"},
			CommonName:   "3x-ui OpenVPN Server",
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
