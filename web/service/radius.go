package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	pending    map[string]time.Time      // key: freshly allocated IP awaiting Acct-Start (User Limit blocks)
	stationIP  map[string]string         // key: "proto:idx:Calling-Station-Id" -> its stable block IP
	stationSeen map[string]time.Time     // last time each station authenticated (for pruning)
	secret     []byte
}

// pendingLeaseTTL is how long a block-allocated IP is held between the
// Access-Accept that assigned it and the Acct-Start that confirms it. An auth
// that never starts a session (retry, abandoned dial) frees the IP after this.
const pendingLeaseTTL = 90 * time.Second

// pendingReclaimGrace is the minimum age of a pending block-lease before it may
// be reclaimed for a different dial. Longer than a normal auth->Acct-Start gap
// (a few seconds), so a device still mid-handshake is never handed its slot to
// someone else; far shorter than pendingLeaseTTL, so a genuinely abandoned
// (ghost) lease is reclaimed promptly instead of wedging the account until TTL.
const pendingReclaimGrace = 15 * time.Second

type radiusSession struct {
	email    string
	ip       string
	protocol string    // "l2tp", "pptp", or "openvpn"
	started  time.Time // Acct-Start time; used to pick the oldest device to evict
}

// runningRadius points at the RadiusService whose servers are currently bound.
// The embedded RADIUS server lives in-process (not a child daemon), so the Core
// Settings restart/stop controls act on this instance rather than a PID.
var runningRadius *RadiusService

// Start launches the RADIUS auth (1812) and accounting (1813) servers on localhost.
func (s *RadiusService) Start(secret string) error {
	s.sessions = make(map[string]*radiusSession)
	s.pending = make(map[string]time.Time)
	return s.listen(secret)
}

// listen (re)creates and serves the auth/acct packet servers. It does NOT touch
// the sessions map, so a restart preserves active-session tracking (the map is
// shared by reference with the L2TP/PPTP/OpenVPN services).
func (s *RadiusService) listen(secret string) error {
	s.secret = []byte(secret)

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

	runningRadius = s
	logger.Info("RADIUS: listening on 127.0.0.1:1812 (auth) and :1813 (acct)")
	return nil
}

// Stop gracefully shuts down both RADIUS servers.
func (s *RadiusService) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.authServer != nil {
		s.authServer.Shutdown(ctx)
		s.authServer = nil
	}
	if s.acctServer != nil {
		s.acctServer.Shutdown(ctx)
		s.acctServer = nil
	}
}

// StopRadius stops the embedded RADIUS servers. Exported for the Core Settings
// "Stop" control. Note: this halts L2TP/PPTP/OpenVPN authentication until a
// restart, so it is a deliberate, admin-triggered action.
func StopRadius() error {
	if runningRadius == nil {
		return fmt.Errorf("RADIUS server is not running")
	}
	runningRadius.Stop()
	logger.Info("RADIUS: stopped")
	return nil
}

// RestartRadius restarts the embedded RADIUS servers, picking up the current
// shared secret from settings. The in-memory session map is preserved.
func RestartRadius() error {
	if runningRadius == nil {
		return fmt.Errorf("RADIUS server is not running")
	}
	var settingService SettingService
	secret, _ := settingService.GetRadiusSecret()
	if secret == "" {
		secret = string(runningRadius.secret)
	}
	runningRadius.Stop()
	if runningRadius.sessions == nil {
		runningRadius.sessions = make(map[string]*radiusSession)
	}
	return runningRadius.listen(secret)
}

// handleAuth processes RADIUS Access-Request packets with MS-CHAPv2 authentication.
// NAS-Identifier encodes the protocol and inbound ID (e.g. "l2tp-3" or "pptp-5").
func (s *RadiusService) handleAuth(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
	response := microsoft.MSCHAP2Response_Get(r.Packet)

	// The client's Calling-Station-Id (its remote IP) is stable across a device's
	// re-authentication/redial, unlike the RADIUS session-id or NAS-Port — so it keys
	// the per-device block-IP assignment for User Limit K>1 (see allocateBlockIP).
	station := rfc2865.CallingStationID_GetString(r.Packet)

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
	microsoft.MSMPPEEncryptionPolicy_Add(accept, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionRequired)
	// 128-bit only: with "40or128 allowed" the server pppd settles on weak 40-bit
	// MPPE (offers +L -S), which 128-bit-requiring clients (Windows/NM default)
	// reject with "MPPE required but peer negotiation failed".
	microsoft.MSMPPEEncryptionTypes_Add(accept, microsoft.MSMPPEEncryptionTypes_Value_RC4128bitAllowed)

	// Assign deterministic IP so per-user Xray routing works via source IP. A deny
	// means the account is at its User Limit and the strategy is "reject".
	clientIP, deny := s.getClientIP(protocol, inboundId, username, station)
	if deny {
		logger.Infof("RADIUS: auth rejected — user-limit reached (strategy=reject) user=%s nas=%s", username, nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}
	if clientIP != nil {
		rfc2865.FramedIPAddress_Set(accept, clientIP)
	}

	// Request periodic accounting updates (60s minimum for pppd)
	rfc2869.AcctInterimInterval_Set(accept, rfc2869.AcctInterimInterval(60))

	logger.Infof("RADIUS: auth accepted user=%s nas=%s ip=%v", username, nasID, clientIP)
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
			started:  time.Now(),
		}
		delete(s.pending, ip) // confirmed: the session now holds this block IP
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
			// Fold the final counter bytes (accumulated since the last 10s collection)
			// into the client's quota BEFORE the counters are deleted — otherwise a
			// disconnect (or a rapid reconnect) silently drops that traffic, which
			// under-counts usage and under-enforces limits.
			up, down := s.nftService.ReadAndResetClientCounters(sess.protocol, sess.ip)
			if (up > 0 || down > 0) && sess.email != "" {
				if db := database.GetDB(); db != nil {
					db.Exec("UPDATE client_traffics SET up = up + ?, down = down + ? WHERE email = ?",
						up, down, sess.email)
				}
			}
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
						started:  time.Now(),
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
	if inboundId > 0 {
		if err := db.First(&inbound, inboundId).Error; err != nil {
			return "", fmt.Errorf("inbound %d not found", inboundId)
		}
	} else {
		// Protocol-level NAS-Identifier: resolve the account to its inbound by name.
		ib, err := s.findClientInbound(protocol, username)
		if err != nil {
			return "", err
		}
		inbound = *ib
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

// parseNASIdentifier extracts protocol and inbound ID from a NAS-Identifier.
// Two forms are accepted:
//   - protocol-level, e.g. "l2tp" / "pptp": inboundId is 0, meaning "resolve the
//     account to its owning inbound by username". This is what the shared daemon
//     configs now send — one xl2tpd/pptpd instance serves every inbound of a
//     protocol on its single fixed port, so it can carry only ONE NAS-Identifier.
//   - per-inbound, e.g. "l2tp-3" / "pptp-5": kept for backward compatibility.
func parseNASIdentifier(nasID string) (protocol string, inboundId int, err error) {
	if nasID == "l2tp" || nasID == "pptp" || nasID == "openvpn" {
		return nasID, 0, nil
	}

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

// findClientInbound locates the enabled inbound of the given protocol whose
// settings contain a client with this username. Used when the RADIUS request
// carries a protocol-level NAS-Identifier (inboundId 0): a single shared
// xl2tpd/pptpd config serves all inbounds of a protocol, so the account is mapped
// to its owning inbound here rather than via the NAS-Identifier. Usernames are
// expected to be unique across a protocol's inbounds; the first match wins.
func (s *RadiusService) findClientInbound(protocol, username string) (*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ? AND enable = ?", protocol, true).Find(&inbounds).Error; err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		var settings struct {
			Clients []struct {
				ID string `json:"id"`
			} `json:"clients"`
		}
		if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
			continue
		}
		for _, c := range settings.Clients {
			if c.ID == username {
				return inbound, nil
			}
		}
	}
	return nil, fmt.Errorf("client %s not found in any %s inbound", username, protocol)
}

// getClientIP computes the deterministic IP for a VPN client. Returns (nil,false)
// if the client is not found or the range is exhausted, and (nil,true) when the
// account is at its User Limit and the strategy is "reject" — the caller must then
// send an Access-Reject rather than a keyless Access-Accept.
func (s *RadiusService) getClientIP(protocol string, inboundId int, username, station string) (net.IP, bool) {
	db := database.GetDB()
	var inbound model.Inbound
	if inboundId > 0 {
		if err := db.First(&inbound, inboundId).Error; err != nil {
			return nil, false
		}
	} else {
		// Protocol-level NAS-Identifier: resolve the account to its inbound by name.
		ib, err := s.findClientInbound(protocol, username)
		if err != nil {
			return nil, false
		}
		inbound = *ib
	}

	type clientEntry struct {
		ID string `json:"id"`
	}
	type settingsJSON struct {
		IpRanges          []string      `json:"ipRanges"`
		IpRange           string        `json:"ipRange"`
		LocalIp           string        `json:"localIp"`
		UserLimit         int           `json:"userLimit"`
		UserLimitStrategy string        `json:"userLimitStrategy"`
		Clients           []clientEntry `json:"clients"`
	}

	var settings settingsJSON
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return nil, false
	}

	clientIndex := -1
	for i, c := range settings.Clients {
		if c.ID == username {
			clientIndex = i
			break
		}
	}
	if clientIndex < 0 {
		return nil, false
	}

	ranges := settings.IpRanges
	if len(ranges) == 0 && settings.IpRange != "" {
		ranges = []string{settings.IpRange}
	}

	// User Limit K>=2 (L2TP/PPTP only — OpenVPN ignores the RADIUS Framed-IP and
	// assigns from its own pool in the connect hook): hand out a FREE IP from the
	// account's block so K devices on one account each get a distinct IP. When the
	// block is full the strategy decides: "reject" denies the dial, "accept" evicts
	// the oldest device. K==1 (and OpenVPN) keeps the legacy per-index IP.
	k := normUserLimit(settings.UserLimit)
	if protocol != "openvpn" && k > 1 {
		subnets := pppSubnetsOrDefault(ranges, protocol, inbound.Id)
		strategy := normUserLimitStrategy(settings.UserLimitStrategy)
		return s.allocateBlockIP(clientIndex, k, subnets, protocol, strategy, station)
	}
	return computeVpnClientIP(ranges, inbound.Id, clientIndex, protocol), false
}

// allocateBlockIP assigns a stable IP inside account `clientIndex`'s K-block (User
// Limit) to the calling device. Devices are keyed by `station` (Calling-Station-Id):
// a device that re-authenticates keeps the IP it already holds (idempotent), so an
// unstable/redialing client can't evict itself and reset its traffic counter, nor be
// handed another device's IP. A new device takes a free slot; when all K are held the
// strategy decides — "reject" returns (nil,true) so the caller denies, "accept" evicts
// the account's OLDEST live device. Returns (ip,false) on success, (nil,true) on deny.
func (s *RadiusService) allocateBlockIP(clientIndex, k int, subnets []string, protocol, strategy, station string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = make(map[string]time.Time)
	}
	if s.stationIP == nil {
		s.stationIP = make(map[string]string)
		s.stationSeen = make(map[string]time.Time)
	}
	now := time.Now()

	// This account's K device IPs.
	isBlockIP := make(map[string]bool, k)
	blockIPs := make([]string, 0, k)
	for d := 0; d < k; d++ {
		if ip := vpnAccountDeviceIP(subnets, clientIndex, k, d); ip != "" {
			isBlockIP[ip] = true
			blockIPs = append(blockIPs, ip)
		}
	}

	skey := ""
	if station != "" {
		skey = fmt.Sprintf("%s:%d:%s", protocol, clientIndex, station)
	}

	// assign claims ip for this station: it wins the slot, so drop any OTHER station's
	// stale claim on the same ip, record ours, and reserve it (pending) until Acct-Start.
	assign := func(ip string) (net.IP, bool) {
		if skey != "" {
			for key, oip := range s.stationIP {
				if oip == ip && key != skey {
					delete(s.stationIP, key)
					delete(s.stationSeen, key)
				}
			}
			s.stationIP[skey] = ip
			s.stationSeen[skey] = now
		}
		s.pending[ip] = now
		return net.ParseIP(ip).To4(), false
	}

	// IDEMPOTENT REDIAL: a client (by Calling-Station-Id) keeps the block IP it already
	// holds — no eviction, no counter churn. Without this, a device whose CHAP/tunnel
	// flaps re-authenticates every ~1s, is treated as a new device each time, evicts its
	// own prior session (resetting that IP's traffic counter -> "counted delta 0") and
	// can be handed the account's other device's IP (duplicate).
	if skey != "" {
		if ip, ok := s.stationIP[skey]; ok && isBlockIP[ip] {
			s.stationSeen[skey] = now
			s.pending[ip] = now
			return net.ParseIP(ip).To4(), false
		}
		// Prune long-abandoned station claims (client gone for good) so the map can't
		// grow without bound; active clients refresh their timestamp just above.
		for key, ts := range s.stationSeen {
			if now.Sub(ts) > pendingLeaseTTL {
				delete(s.stationSeen, key)
				delete(s.stationIP, key)
			}
		}
	}

	// Real occupancy = live session IPs + still-valid pending allocations (a lingering
	// station claim with no session/pending does NOT block a new device). Expired
	// pending leases (auth without a following Acct-Start) are reclaimed here.
	used := make(map[string]bool, len(s.sessions)+len(s.pending))
	for _, sess := range s.sessions {
		used[sess.ip] = true
	}
	for ip, ts := range s.pending {
		if now.Sub(ts) > pendingLeaseTTL {
			delete(s.pending, ip)
			continue
		}
		used[ip] = true
	}

	// (1) A free slot for this new device.
	blockSet := make(map[string]bool, k)
	for _, ip := range blockIPs {
		blockSet[ip] = true
		if !used[ip] {
			return assign(ip)
		}
	}

	// (2) Reclaim the OLDEST abandoned gap-lease (pending older than the grace) before
	// evicting/denying. A fresh in-flight dial (younger than the grace) and a live
	// session (never in s.pending — cleared at Acct-Start) are both left untouched.
	var ghostIP string
	var ghostTS time.Time
	for _, ip := range blockIPs {
		if ts, ok := s.pending[ip]; ok && now.Sub(ts) > pendingReclaimGrace {
			if ghostIP == "" || ts.Before(ghostTS) {
				ghostIP, ghostTS = ip, ts
			}
		}
	}
	if ghostIP != "" {
		return assign(ghostIP)
	}

	// (3) Block full. "accept": evict the account's oldest live device and reuse its IP.
	if strategy == "accept" {
		if victimSID, victimIP := oldestBlockSession(s.sessions, blockSet); victimIP != "" {
			delete(s.sessions, victimSID)
			s.nftService.RemoveClientAccounting(protocol, victimIP)
			killPPPByIP(victimIP) // force the old device's ppp link down
			logger.Infof("RADIUS: user-limit accept — evicted oldest device ip=%s proto=%s to admit new device", victimIP, protocol)
			return assign(victimIP)
		}
		// No live device to evict (all slots pending/mid-handshake) — deny for now.
	}

	// "reject" (default) or nothing evictable: deny the dial.
	return nil, true
}

// oldestBlockSession returns the (session id, IP) of the longest-connected live
// session whose IP falls inside blockIPs (one account's K device IPs), or ("","")
// when none do. Pure selection — the eviction side effects (nft/kill/pending) are
// the caller's.
func oldestBlockSession(sessions map[string]*radiusSession, blockIPs map[string]bool) (sid, ip string) {
	var started time.Time
	for id, sess := range sessions {
		if !blockIPs[sess.ip] {
			continue
		}
		if sid == "" || sess.started.Before(started) {
			sid, ip, started = id, sess.ip, sess.started
		}
	}
	return sid, ip
}

// killPPPByIP force-disconnects an L2TP/PPTP device by deleting the PPP interface
// whose peer address is ip (freeing the tunnel IP). The supervising daemon reaps
// the orphaned pppd. Best-effort: any lookup/exec error is ignored.
func killPPPByIP(ip string) {
	out, err := exec.Command("ip", "-o", "addr", "show").Output()
	if err != nil {
		return
	}
	needle := "peer " + ip + "/"
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := strings.TrimSuffix(fields[1], ":") // "3: ppp0 ..." -> "ppp0"
		if !strings.HasPrefix(iface, "ppp") {
			continue
		}
		_ = exec.Command("ip", "link", "delete", iface).Run()
		return
	}
}

// computeVpnClientIP computes the deterministic IP for the L2TP/PPTP client at
// the given index by walking the inbound's ranges in order: the client lives in
// the range whose cumulative capacity first exceeds the index. Returns nil only
// when the index exceeds the total capacity of every range (the normalizer keeps
// capacity ahead of the client count so this should not happen in practice).
func computeVpnClientIP(ranges []string, inboundId, clientIndex int, protocol string) net.IP {
	if len(ranges) == 0 {
		ranges = []string{defaultRange(fmt.Sprintf("10.%d.%d", protocolBase(protocol), inboundId))}
	}

	remaining := clientIndex
	for _, r := range ranges {
		start, end, ok := parseRange(r)
		if !ok {
			continue
		}
		capacity := int(end[3]) - int(start[3]) + 1
		if remaining < capacity {
			ip := make(net.IP, 4)
			copy(ip, start)
			ip[3] += byte(remaining)
			return ip
		}
		remaining -= capacity
	}
	return nil
}

// BuildVpnEmailToIPMap returns a map of email → deterministic tunnel IP(s) for all
// enabled L2TP/PPTP/OpenVPN clients. Used by the Xray config generator to translate
// email-based routing rules into source-IP rules. Values are slices: an OpenVPN
// client maps to one IP per enabled transport, and under User Limit K>=2 every
// account maps to its K device IPs (times the enabled transports for OpenVPN).
func BuildVpnEmailToIPMap() map[string][]string {
	result := make(map[string][]string)
	db := database.GetDB()
	if db == nil {
		return result
	}

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	// --- L2TP / PPTP: single IP from the ppp ip-range ---
	var pppInbounds []*model.Inbound
	db.Where("protocol IN ? AND enable = ?", []string{"l2tp", "pptp"}, true).Find(&pppInbounds)

	type pppSettingsJSON struct {
		IpRanges  []string      `json:"ipRanges"`
		IpRange   string        `json:"ipRange"`
		UserLimit int           `json:"userLimit"`
		Clients   []clientEntry `json:"clients"`
	}

	for _, inbound := range pppInbounds {
		var settings pppSettingsJSON
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		ranges := settings.IpRanges
		if len(ranges) == 0 && settings.IpRange != "" {
			ranges = []string{settings.IpRange}
		}
		k := normUserLimit(settings.UserLimit)
		// K>=2: each account maps to its K device IPs, so one source rule (an
		// explicit IP list) covers every device. K==1 keeps the legacy single IP.
		subnets := pppSubnetsOrDefault(ranges, string(inbound.Protocol), inbound.Id)
		for i, client := range settings.Clients {
			if client.Email == "" {
				continue
			}
			if k <= 1 {
				if ip := computeVpnClientIP(ranges, inbound.Id, i, string(inbound.Protocol)); ip != nil {
					result[client.Email] = append(result[client.Email], ip.String())
				}
			} else {
				result[client.Email] = append(result[client.Email], vpnAccountDeviceIPs(subnets, i, k)...)
			}
		}
	}

	// --- OpenVPN: one deterministic CCD IP per enabled transport block ---
	var ovpnInbounds []*model.Inbound
	db.Where("protocol = ? AND enable = ?", "openvpn", true).Find(&ovpnInbounds)

	for _, inbound := range ovpnInbounds {
		var settings openvpnSettings
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		udpOn := settings.udpEnabled()
		tcpOn := settings.tcpEnabled()
		k := normUserLimit(settings.UserLimit)
		var udpNet, tcpNet net.IP
		var udpPrefix, tcpPrefix int
		if udpOn {
			udpNet, udpPrefix = ovpnBlockFor(inbound, &settings, "udp")
		}
		if tcpOn {
			tcpNet, tcpPrefix = ovpnBlockFor(inbound, &settings, "tcp")
		}
		// K>=2: per-account device IP lists (one block per enabled transport). K==1
		// keeps the legacy single continuous per-index IP per transport.
		udpSubnets := ovpnSubnetsOrDefault(&settings, "udp", inbound.Id)
		tcpSubnets := ovpnSubnetsOrDefault(&settings, "tcp", inbound.Id)
		for i, client := range settings.Clients {
			if client.Email == "" {
				continue
			}
			if k <= 1 {
				if udpOn {
					if ip := ovpnBlockClientIP(udpNet, udpPrefix, i); ip != "" {
						result[client.Email] = append(result[client.Email], ip)
					}
				}
				if tcpOn {
					if ip := ovpnBlockClientIP(tcpNet, tcpPrefix, i); ip != "" {
						result[client.Email] = append(result[client.Email], ip)
					}
				}
				continue
			}
			if udpOn {
				result[client.Email] = append(result[client.Email], vpnAccountDeviceIPs(udpSubnets, i, k)...)
			}
			if tcpOn {
				result[client.Email] = append(result[client.Email], vpnAccountDeviceIPs(tcpSubnets, i, k)...)
			}
		}
	}

	return result
}

// pppSubnetsOrDefault returns the ordered /24 prefixes ("A.B.C") an L2TP/PPTP
// inbound owns, falling back to the legacy id-derived /24 when none are stored.
func pppSubnetsOrDefault(ranges []string, proto string, id int) []string {
	if subs := subnetsOf(ranges); len(subs) > 0 {
		return subs
	}
	return []string{fmt.Sprintf("10.%d.%d", protocolBase(proto), id)}
}

// ovpnSubnetsOrDefault returns the ordered /24 prefixes for an OpenVPN transport
// (udp => 10.2.x, tcp => 10.3.x mirror), falling back to the legacy id-derived
// /24 when no ranges are stored.
func ovpnSubnetsOrDefault(settings *openvpnSettings, proto string, id int) []string {
	subs := subnetsOf(settings.effectiveRanges())
	if len(subs) == 0 {
		second := 2
		if proto == "tcp" {
			second = 3
		}
		return []string{fmt.Sprintf("10.%d.%d", second, id)}
	}
	if proto == "tcp" {
		out := make([]string, len(subs))
		for i, s := range subs {
			out[i] = mirrorOvpnSubnet(s)
		}
		return out
	}
	return subs
}

// GenerateRadiusClientConfig writes the radcli config file for a protocol. One
// shared xl2tpd/pptpd instance serves EVERY inbound of a protocol on its single
// fixed port, so there is one radcli config per protocol (not per inbound), at
// /etc/ppp/radius/{protocol}.conf, carrying a protocol-level nas_identifier
// ({protocol}). The RADIUS server then resolves each account to its owning inbound
// by username (see findClientInbound). Also writes the shared servers file and a
// self-contained dictionary with Microsoft VSAs (pppd's static radiusclient parser
// uses INCLUDE not $INCLUDE, so we can't rely on /etc/radcli/dictionary).
func GenerateRadiusClientConfig(protocol string, secret string) error {
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

	// Per-protocol config (shared by all inbounds of that protocol).
	seqFile := fmt.Sprintf("/var/run/radius-%s.seq", protocol)
	config := fmt.Sprintf(`# Auto-generated by vpn-ui RADIUS — do not edit
authserver	127.0.0.1:1812
acctserver	127.0.0.1:1813
servers		%s/servers
dictionary	%s/dictionary
mapfile		%s/port-id-map
nas_identifier	%s
radius_timeout	5
radius_retries	3
seqfile		%s
`, dir, dir, dir, protocol, seqFile)

	configPath := fmt.Sprintf("%s/%s.conf", dir, protocol)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	// Shared servers file
	servers := fmt.Sprintf("127.0.0.1\t%s\n", secret)
	return os.WriteFile(dir+"/servers", []byte(servers), 0600)
}

// cleanupLegacyPerInboundFiles removes stale per-inbound PPP options and radcli
// config files left by the previous layout (one set per inbound), now that a single
// shared set is used per protocol. Best-effort: unreferenced leftovers are harmless,
// but removing them keeps /etc/ppp tidy across an upgrade. optionsPrefix is the PPP
// options basename ("options.xl2tpd" or "pptpd-options"); the shared file (no "-N"
// suffix) is not matched by the "-*" globs, so it is preserved.
func cleanupLegacyPerInboundFiles(optionsPrefix, protocol string) {
	for _, pattern := range []string{
		"/etc/ppp/" + optionsPrefix + "-*",
		"/etc/ppp/radius/" + protocol + "-*.conf",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, f := range matches {
			_ = os.Remove(f)
		}
	}
}

// generateRadiusDictionary writes a self-contained RADIUS dictionary at dir/dictionary.
// Includes standard RFC 2865/2866 attributes + Microsoft VSAs for MS-CHAPv2 + MPPE.
// This avoids depending on /etc/radcli/dictionary which uses $INCLUDE syntax
// that pppd's statically linked radiusclient parser cannot parse.
func generateRadiusDictionary(dir string) error {
	dict := `# Auto-generated by vpn-ui — RADIUS dictionary for pppd
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
