package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3079"
	"layeh.com/radius/vendors/microsoft"
)

// RadiusService embeds a RADIUS server for PPP (L2TP/PPTP) authentication and accounting.
// Auth: pppd sends Access-Request with MS-CHAPv2 → we query SQLite → Accept/Reject.
// Acct: pppd sends Acct-Start/Stop → we manage nft counters and track sessions in memory.
type RadiusService struct {
	nftService NftService
	authServer *radius.PacketServer
	acctServer *radius.PacketServer
	mu         sync.Mutex
	sessions   map[string]*radiusSession // key: Acct-Session-Id
	secret     []byte
}

type radiusSession struct {
	email    string
	ip       string
	protocol string // "l2tp", "pptp", or "openvpn"
}

// Start launches the RADIUS auth (1812) and accounting (1813) servers on localhost.
func (s *RadiusService) Start(secret string) error {
	s.secret = []byte(secret)
	s.sessions = make(map[string]*radiusSession)

	s.authServer = &radius.PacketServer{
		Addr:         "127.0.0.1:1812",
		Handler:      radius.HandlerFunc(s.handleAuth),
		SecretSource: radius.StaticSecretSource(s.secret),
	}
	s.acctServer = &radius.PacketServer{
		Addr:         "127.0.0.1:1813",
		Handler:      radius.HandlerFunc(s.handleAcct),
		SecretSource: radius.StaticSecretSource(s.secret),
	}

	go func() {
		if err := s.authServer.ListenAndServe(); err != nil {
			logger.Warning("RADIUS: auth server stopped:", err)
		}
	}()
	go func() {
		if err := s.acctServer.ListenAndServe(); err != nil {
			logger.Warning("RADIUS: acct server stopped:", err)
		}
	}()

	logger.Info("RADIUS: listening on 127.0.0.1:1812 (auth) and :1813 (acct)")
	return nil
}

// Stop gracefully shuts down both RADIUS servers.
func (s *RadiusService) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.authServer != nil {
		s.authServer.Shutdown(ctx)
	}
	if s.acctServer != nil {
		s.acctServer.Shutdown(ctx)
	}
}

// handleAuth processes RADIUS Access-Request packets with MS-CHAPv2 authentication.
// NAS-Identifier encodes the protocol and inbound ID (e.g. "l2tp-3" or "pptp-5").
func (s *RadiusService) handleAuth(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
	response := microsoft.MSCHAP2Response_Get(r.Packet)

	if username == "" || nasID == "" {
		logger.Debug("RADIUS: auth rejected — missing username or NAS-Identifier")
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Parse NAS-Identifier: "l2tp-{id}" or "pptp-{id}"
	protocol, inboundId, err := parseNASIdentifier(nasID)
	if err != nil {
		logger.Debugf("RADIUS: auth rejected — invalid NAS-Identifier %q", nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Look up the client password from the database
	password, err := s.lookupClient(protocol, inboundId, username)
	if err != nil {
		logger.Debugf("RADIUS: auth rejected — %s user=%s nas=%s", err, username, nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// PAP authentication (OpenVPN sends plaintext password via User-Password)
	userPassword := rfc2865.UserPassword_GetString(r.Packet)
	if userPassword != "" {
		if userPassword == password {
			accept := r.Response(radius.CodeAccessAccept)
			logger.Infof("RADIUS: auth accepted (PAP) user=%s nas=%s", username, nasID)
			w.Write(accept)
		} else {
			logger.Debugf("RADIUS: auth rejected (PAP) — wrong password user=%s nas=%s", username, nasID)
			w.Write(r.Response(radius.CodeAccessReject))
		}
		return
	}

	// MS-CHAPv2 authentication
	if len(challenge) != 16 || len(response) != 50 {
		logger.Debugf("RADIUS: auth rejected — bad MS-CHAPv2 lengths (challenge=%d response=%d) user=%s",
			len(challenge), len(response), username)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	ident := response[0]
	peerChallenge := response[2:18]
	peerResponse := response[26:50]

	ntResponse, err := rfc2759.GenerateNTResponse(challenge, peerChallenge, []byte(username), []byte(password))
	if err != nil {
		logger.Warning("RADIUS: GenerateNTResponse failed:", err)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if !bytes.Equal(ntResponse, peerResponse) {
		logger.Debugf("RADIUS: auth rejected — wrong password user=%s nas=%s", username, nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Build Access-Accept with MS-CHAPv2 success + MPPE keys
	accept := r.Response(radius.CodeAccessAccept)

	// Authenticator response (S=... string for client verification)
	authResp, _ := rfc2759.GenerateAuthenticatorResponse(challenge, peerChallenge, ntResponse, []byte(username), []byte(password))
	success := make([]byte, 43)
	success[0] = ident
	copy(success[1:], authResp)
	microsoft.MSCHAP2Success_Add(accept, success)

	// MPPE keys (required for PPTP, harmlessly ignored by L2TP)
	recvKey, _ := rfc3079.MakeKey(ntResponse, []byte(password), false)
	sendKey, _ := rfc3079.MakeKey(ntResponse, []byte(password), true)
	microsoft.MSMPPERecvKey_Add(accept, recvKey)
	microsoft.MSMPPESendKey_Add(accept, sendKey)
	microsoft.MSMPPEEncryptionPolicy_Add(accept, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionAllowed)
	microsoft.MSMPPEEncryptionTypes_Add(accept, microsoft.MSMPPEEncryptionTypes_Value_RC440or128BitAllowed)

	// Request periodic accounting updates (60s minimum for pppd)
	rfc2869.AcctInterimInterval_Set(accept, rfc2869.AcctInterimInterval(60))

	logger.Infof("RADIUS: auth accepted user=%s nas=%s", username, nasID)
	w.Write(accept)
}

// handleAcct processes RADIUS Accounting-Request packets (Start/Stop/Interim-Update).
func (s *RadiusService) handleAcct(w radius.ResponseWriter, r *radius.Request) {
	statusType := rfc2866.AcctStatusType_Get(r.Packet)
	sessionID := rfc2866.AcctSessionID_GetString(r.Packet)
	username := rfc2865.UserName_GetString(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	framedIP := rfc2865.FramedIPAddress_Get(r.Packet)

	// Always acknowledge
	defer w.Write(r.Response(radius.CodeAccountingResponse))

	protocol, _, err := parseNASIdentifier(nasID)
	if err != nil {
		logger.Debugf("RADIUS: acct ignored — invalid NAS-Identifier %q", nasID)
		return
	}

	switch statusType {
	case rfc2866.AcctStatusType_Value_Start:
		ip := framedIP.String()
		if ip == "<nil>" || ip == "" {
			logger.Debugf("RADIUS: acct-start missing Framed-IP user=%s", username)
			return
		}

		// Look up email for this username
		email := s.lookupEmail(protocol, username)
		if email == "" {
			logger.Debugf("RADIUS: acct-start no email found for user=%s nas=%s", username, nasID)
			return
		}

		s.mu.Lock()
		s.sessions[sessionID] = &radiusSession{
			email:    email,
			ip:       ip,
			protocol: protocol,
		}
		s.mu.Unlock()

		// Add nft accounting counters for this client
		if err := s.nftService.AddClientAccounting(protocol, ip); err != nil {
			logger.Warning("RADIUS: failed to add nft accounting:", err)
		}

		logger.Infof("RADIUS: acct-start user=%s email=%s ip=%s proto=%s session=%s", username, email, ip, protocol, sessionID)

	case rfc2866.AcctStatusType_Value_Stop:
		s.mu.Lock()
		sess, ok := s.sessions[sessionID]
		if ok {
			delete(s.sessions, sessionID)
		}
		s.mu.Unlock()

		if ok {
			// Remove nft accounting counters
			if err := s.nftService.RemoveClientAccounting(sess.protocol, sess.ip); err != nil {
				logger.Warning("RADIUS: failed to remove nft accounting:", err)
			}
			logger.Infof("RADIUS: acct-stop user=%s email=%s ip=%s proto=%s session=%s", username, sess.email, sess.ip, sess.protocol, sessionID)
		} else {
			// Unknown session (e.g. after panel restart) — try cleanup by IP if available
			ip := framedIP.String()
			if ip != "<nil>" && ip != "" {
				s.nftService.RemoveClientAccounting(protocol, ip)
				logger.Infof("RADIUS: acct-stop (orphan) user=%s ip=%s proto=%s session=%s", username, ip, protocol, sessionID)
			} else {
				logger.Debugf("RADIUS: acct-stop unknown session=%s user=%s", sessionID, username)
			}
		}

	case rfc2866.AcctStatusType_Value_InterimUpdate:
		// For L2TP/PPTP we use nft counters, so interim updates are logged but not processed
		logger.Debugf("RADIUS: acct-interim user=%s session=%s", username, sessionID)

		// Re-add session if missing (e.g. after panel restart)
		s.mu.Lock()
		if _, ok := s.sessions[sessionID]; !ok {
			ip := framedIP.String()
			if ip != "<nil>" && ip != "" {
				email := s.lookupEmail(protocol, username)
				if email != "" {
					s.sessions[sessionID] = &radiusSession{
						email:    email,
						ip:       ip,
						protocol: protocol,
					}
					s.mu.Unlock()
					s.nftService.AddClientAccounting(protocol, ip)
					logger.Infof("RADIUS: re-added session from interim user=%s email=%s ip=%s", username, email, ip)
					return
				}
			}
		}
		s.mu.Unlock()
	}
}

// GetSessions returns an IP→email map for the given protocol, used by traffic collection.
func (s *RadiusService) GetSessions(protocol string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]string)
	for _, sess := range s.sessions {
		if sess.protocol == protocol {
			result[sess.ip] = sess.email
		}
	}
	return result
}

// GetActiveSessionEmails returns a set of emails with active sessions (for online status).
func (s *RadiusService) GetActiveSessionEmails() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]bool)
	for _, sess := range s.sessions {
		result[sess.email] = true
	}
	return result
}

// lookupClient queries SQLite for the client password. Returns error if client not found,
// disabled, or traffic-limited.
func (s *RadiusService) lookupClient(protocol string, inboundId int, username string) (string, error) {
	db := database.GetDB()

	var inbound model.Inbound
	if err := db.First(&inbound, inboundId).Error; err != nil {
		return "", fmt.Errorf("inbound %d not found", inboundId)
	}

	if !inbound.Enable {
		return "", fmt.Errorf("inbound %d disabled", inboundId)
	}

	if string(inbound.Protocol) != protocol {
		return "", fmt.Errorf("inbound %d protocol mismatch: expected %s got %s", inboundId, protocol, inbound.Protocol)
	}

	// Parse settings to find the client
	type clientEntry struct {
		ID       string `json:"id"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Enable   bool   `json:"enable"`
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	var settings settingsJSON
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return "", fmt.Errorf("failed to parse settings for inbound %d", inboundId)
	}

	for _, client := range settings.Clients {
		if client.ID == username {
			if !client.Enable {
				return "", fmt.Errorf("client %s disabled in settings", username)
			}

			// Check client_traffics enable (traffic/expiry limits)
			if client.Email != "" {
				var traffic struct{ Enable bool }
				if err := db.Table("client_traffics").
					Select("enable").
					Where("email = ?", client.Email).
					First(&traffic).Error; err == nil && !traffic.Enable {
					return "", fmt.Errorf("client %s traffic limit reached (email=%s)", username, client.Email)
				}
			}

			return client.Password, nil
		}
	}

	return "", fmt.Errorf("client %s not found in inbound %d", username, inboundId)
}

// lookupEmail finds the email for a username across all inbounds of the given protocol.
func (s *RadiusService) lookupEmail(protocol string, username string) string {
	db := database.GetDB()
	var inbounds []*model.Inbound
	db.Where("protocol = ?", protocol).Find(&inbounds)

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	for _, inbound := range inbounds {
		var settings settingsJSON
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if client.ID == username {
				return client.Email
			}
		}
	}
	return ""
}

// KillSessionsByEmail kills pppd processes for all active sessions matching the given emails.
func (s *RadiusService) KillSessionsByEmail(emails map[string]bool) {
	s.mu.Lock()
	var toKill []string
	for _, sess := range s.sessions {
		if emails[sess.email] {
			toKill = append(toKill, sess.ip)
		}
	}
	s.mu.Unlock()

	for _, ip := range toKill {
		// Find and kill pppd by the IP it assigned
		s.killPppdByIP(ip)
	}
}

// killPppdByIP finds and kills the pppd process that owns the given PPP client IP.
func (s *RadiusService) killPppdByIP(ip string) {
	// Check all ppp interfaces for matching IP
	output, err := exec.Command("ip", "-o", "addr", "show").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, ip) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := fields[1]
		if !strings.HasPrefix(iface, "ppp") {
			continue
		}
		// Read PID file for this interface
		pidFile := fmt.Sprintf("/var/run/%s.pid", iface)
		pidData, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid := strings.TrimSpace(string(pidData))
		if pid != "" {
			exec.Command("kill", pid).Run()
			logger.Infof("RADIUS: killed pppd pid=%s iface=%s ip=%s", pid, iface, ip)
		}
	}
}

// CleanStaleSessions removes sessions whose PPP interface no longer exists.
func (s *RadiusService) CleanStaleSessions() {
	s.mu.Lock()
	var stale []string
	for sid, sess := range s.sessions {
		if !s.isIPActive(sess.ip, sess.protocol) {
			stale = append(stale, sid)
		}
	}
	for _, sid := range stale {
		sess := s.sessions[sid]
		delete(s.sessions, sid)
		s.mu.Unlock()
		s.nftService.RemoveClientAccounting(sess.protocol, sess.ip)
		logger.Infof("RADIUS: cleaned stale session=%s email=%s ip=%s", sid, sess.email, sess.ip)
		s.mu.Lock()
	}
	s.mu.Unlock()
}

// isIPActive checks if a PPP client IP is still assigned to an interface.
func (s *RadiusService) isIPActive(ip string, protocol string) bool {
	// For L2TP/PPTP: check if the IP is assigned to a local PPP interface
	if protocol != "openvpn" {
		output, err := exec.Command("ip", "-o", "addr", "show").Output()
		if err != nil {
			return true // assume active on error
		}
		return strings.Contains(string(output), ip)
	}

	// For OpenVPN: check if a route to the IP exists through a tun device
	output, err := exec.Command("ip", "route", "get", ip).Output()
	if err != nil {
		return false // no route = not active
	}
	return strings.Contains(string(output), "tun-ovpn")
}

// parseNASIdentifier extracts protocol and inbound ID from "l2tp-{id}" or "pptp-{id}".
func parseNASIdentifier(nasID string) (protocol string, inboundId int, err error) {
	parts := strings.SplitN(nasID, "-", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid NAS-Identifier format: %s", nasID)
	}

	protocol = parts[0]
	if protocol != "l2tp" && protocol != "pptp" && protocol != "openvpn" {
		return "", 0, fmt.Errorf("unknown protocol in NAS-Identifier: %s", protocol)
	}

	_, err = fmt.Sscanf(parts[1], "%d", &inboundId)
	if err != nil {
		return "", 0, fmt.Errorf("invalid inbound ID in NAS-Identifier: %s", nasID)
	}

	return protocol, inboundId, nil
}

// GenerateRadiusClientConfig writes the radcli config files for a given inbound.
// Creates per-inbound config at /etc/ppp/radius/{protocol}-{id}.conf, shared servers file,
// and a self-contained dictionary with Microsoft VSAs (pppd's static radiusclient
// parser uses INCLUDE not $INCLUDE, so we can't rely on /etc/radcli/dictionary).
func GenerateRadiusClientConfig(protocol string, inboundId int, secret string) error {
	dir := "/etc/ppp/radius"
	os.MkdirAll(dir, 0755)

	// Create empty mapfile (port-id-map) if it doesn't exist — required by libradcli
	mapFile := dir + "/port-id-map"
	if _, err := os.Stat(mapFile); os.IsNotExist(err) {
		os.WriteFile(mapFile, []byte(""), 0644)
	}

	// Generate self-contained dictionary (written once, same content every time)
	if err := generateRadiusDictionary(dir); err != nil {
		return fmt.Errorf("failed to write dictionary: %w", err)
	}

	// Per-inbound config
	seqFile := fmt.Sprintf("/var/run/radius-%s-%d.seq", protocol, inboundId)
	config := fmt.Sprintf(`# Auto-generated by 3x-ui RADIUS — do not edit
authserver	127.0.0.1:1812
acctserver	127.0.0.1:1813
servers		%s/servers
dictionary	%s/dictionary
mapfile		%s/port-id-map
nas_identifier	%s-%d
radius_timeout	5
radius_retries	3
seqfile		%s
`, dir, dir, dir, protocol, inboundId, seqFile)

	configPath := fmt.Sprintf("%s/%s-%d.conf", dir, protocol, inboundId)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	// Shared servers file
	servers := fmt.Sprintf("127.0.0.1\t%s\n", secret)
	return os.WriteFile(dir+"/servers", []byte(servers), 0600)
}

// generateRadiusDictionary writes a self-contained RADIUS dictionary at dir/dictionary.
// Includes standard RFC 2865/2866 attributes + Microsoft VSAs for MS-CHAPv2 + MPPE.
// This avoids depending on /etc/radcli/dictionary which uses $INCLUDE syntax
// that pppd's statically linked radiusclient parser cannot parse.
func generateRadiusDictionary(dir string) error {
	dict := `# Auto-generated by 3x-ui — RADIUS dictionary for pppd
# Standard RADIUS attributes (RFC 2865)
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	User-Password		2	string
ATTRIBUTE	CHAP-Password		3	string
ATTRIBUTE	NAS-IP-Address		4	ipaddr
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Service-Type		6	integer
ATTRIBUTE	Framed-Protocol		7	integer
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Framed-IP-Netmask	9	ipaddr
ATTRIBUTE	Framed-Routing		10	integer
ATTRIBUTE	Filter-Id		11	string
ATTRIBUTE	Framed-MTU		12	integer
ATTRIBUTE	Framed-Compression	13	integer
ATTRIBUTE	Reply-Message		18	string
ATTRIBUTE	State			24	string
ATTRIBUTE	Class			25	string
ATTRIBUTE	Session-Timeout		27	integer
ATTRIBUTE	Idle-Timeout		28	integer
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	Acct-Status-Type	40	integer
ATTRIBUTE	Acct-Delay-Time		41	integer
ATTRIBUTE	Acct-Input-Octets	42	integer
ATTRIBUTE	Acct-Output-Octets	43	integer
ATTRIBUTE	Acct-Session-Id		44	string
ATTRIBUTE	Acct-Authentic		45	integer
ATTRIBUTE	Acct-Session-Time	46	integer
ATTRIBUTE	Acct-Input-Packets	47	integer
ATTRIBUTE	Acct-Output-Packets	48	integer
ATTRIBUTE	CHAP-Challenge		60	string
ATTRIBUTE	NAS-Port-Type		61	integer
ATTRIBUTE	Acct-Interim-Interval	85	integer

# Microsoft vendor-specific attributes (RFC 2548)
VENDOR		Microsoft	311

ATTRIBUTE	MS-CHAP-Response	1	string	Microsoft
ATTRIBUTE	MS-CHAP-Error		2	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-1		3	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-2		4	string	Microsoft
ATTRIBUTE	MS-CHAP-LM-Enc-PW	5	string	Microsoft
ATTRIBUTE	MS-CHAP-NT-Enc-PW	6	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Policy 7	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Type	8	string	Microsoft
ATTRIBUTE	MS-CHAP-Challenge	11	string	Microsoft
ATTRIBUTE	MS-CHAP-MPPE-Keys	12	string	Microsoft
ATTRIBUTE	MS-MPPE-Send-Key	16	string	Microsoft
ATTRIBUTE	MS-MPPE-Recv-Key	17	string	Microsoft
ATTRIBUTE	MS-CHAP2-Response	25	string	Microsoft
ATTRIBUTE	MS-CHAP2-Success	26	string	Microsoft
`
	return os.WriteFile(dir+"/dictionary", []byte(dict), 0644)
}
