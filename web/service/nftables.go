package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

const nftConfigFile = "/etc/x-ui/vpn.nft"

// NftService manages nftables rules for L2TP, PPTP, and OpenVPN traffic accounting, TPROXY, and NAT.
type NftService struct{}

// ApplyNftRules regenerates and atomically loads the nftables config for all VPN inbounds.
// Static chains (prerouting/postrouting/input) are flushed and rebuilt.
// Accounting chains (l2tp_acct/pptp_acct) are NEVER flushed — their dynamic per-client
// rules (added by ip-up.d scripts) survive across regenerations.
func (s *NftService) ApplyNftRules() error {
	l2tp := L2tpService{}
	pptp := PptpService{}
	ovpn := OpenVpnService{}

	l2tpInbounds, err := l2tp.GetL2tpInbounds()
	if err != nil {
		return err
	}
	pptpInbounds, err := pptp.GetPptpInbounds()
	if err != nil {
		return err
	}
	ovpnInbounds, err := ovpn.GetOpenVpnInbounds()
	if err != nil {
		return err
	}

	// If no VPN inbounds, remove the table entirely
	if len(l2tpInbounds) == 0 && len(pptpInbounds) == 0 && len(ovpnInbounds) == 0 {
		s.runCmd("nft", "delete", "table", "ip", "vpn")
		os.Remove(nftConfigFile)
		return nil
	}

	var b strings.Builder

	// Create table and chains (idempotent — 'add' doesn't error if they already exist)
	b.WriteString("add table ip vpn\n")
	b.WriteString("add chain ip vpn l2tp_acct\n")
	b.WriteString("add chain ip vpn pptp_acct\n")
	b.WriteString("add chain ip vpn openvpn_acct\n")
	b.WriteString("add chain ip vpn prerouting { type filter hook prerouting priority mangle; policy accept; }\n")
	b.WriteString("add chain ip vpn postrouting { type filter hook postrouting priority mangle; policy accept; }\n")
	b.WriteString("add chain ip vpn input { type filter hook input priority filter; policy accept; }\n")

	// Flush only static chains (accounting chains are dynamic, never flushed)
	b.WriteString("flush chain ip vpn prerouting\n")
	b.WriteString("flush chain ip vpn postrouting\n")
	b.WriteString("flush chain ip vpn input\n")

	// Accounting jumps (must be before TPROXY so packets are counted before accept)
	b.WriteString("add rule ip vpn prerouting jump l2tp_acct\n")
	b.WriteString("add rule ip vpn prerouting jump pptp_acct\n")
	b.WriteString("add rule ip vpn prerouting jump openvpn_acct\n")
	b.WriteString("add rule ip vpn postrouting jump l2tp_acct\n")
	b.WriteString("add rule ip vpn postrouting jump pptp_acct\n")
	b.WriteString("add rule ip vpn postrouting jump openvpn_acct\n")

	// L2TP TPROXY rules
	for _, inbound := range l2tpInbounds {
		if !inbound.Enable {
			continue
		}
		subnet := l2tp.GetSubnetForInbound(inbound)
		port := l2tp.GetTproxyPort(inbound)
		src := fmt.Sprintf("%s.0/24", subnet)
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
	}

	// PPTP TPROXY rules
	for _, inbound := range pptpInbounds {
		if !inbound.Enable {
			continue
		}
		subnet := pptp.GetSubnetForInbound(inbound)
		port := pptp.GetTproxyPort(inbound)
		src := fmt.Sprintf("%s.0/24", subnet)
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
	}

	// Raw L2TP filter: block non-IPsec L2TP when ipsecEnable && !allowRaw
	needFilter := false
	for _, inbound := range l2tpInbounds {
		settings, err := l2tp.parseSettings(inbound)
		if err != nil {
			continue
		}
		if settings.IpsecEnable && !settings.AllowRaw {
			needFilter = true
			break
		}
	}
	if needFilter {
		// Accept L2TP that arrived via IPsec, drop the rest
		b.WriteString("add rule ip vpn input udp dport 1701 meta secpath exists accept\n")
		b.WriteString("add rule ip vpn input udp dport 1701 drop\n")
	}

	// NAT for OpenVPN subnets (direct internet, no TPROXY)
	if len(ovpnInbounds) > 0 {
		b.WriteString("add chain ip vpn nat_post { type nat hook postrouting priority srcnat; policy accept; }\n")
		b.WriteString("flush chain ip vpn nat_post\n")
		for _, inbound := range ovpnInbounds {
			if !inbound.Enable {
				continue
			}
			// UDP subnet: 10.2.{id}.0/24, TCP subnet: 10.3.{id}.0/24
			b.WriteString(fmt.Sprintf("add rule ip vpn nat_post ip saddr 10.2.%d.0/24 masquerade\n", inbound.Id))
			b.WriteString(fmt.Sprintf("add rule ip vpn nat_post ip saddr 10.3.%d.0/24 masquerade\n", inbound.Id))
		}
	}

	// Write and load atomically
	if err := os.MkdirAll("/etc/x-ui", 0755); err != nil {
		return err
	}
	if err := os.WriteFile(nftConfigFile, []byte(b.String()), 0644); err != nil {
		return err
	}
	if err := s.runCmd("nft", "-f", nftConfigFile); err != nil {
		return fmt.Errorf("failed to load nft rules: %w", err)
	}

	logger.Infof("nft: loaded VPN rules (%d L2TP, %d PPTP, %d OpenVPN inbounds)", len(l2tpInbounds), len(pptpInbounds), len(ovpnInbounds))
	return nil
}

// nftCounterOutput represents the JSON output of `nft -j reset counters`.
type nftCounterOutput struct {
	Nftables []json.RawMessage `json:"nftables"`
}

type nftCounterEntry struct {
	Counter *nftCounter `json:"counter"`
}

type nftCounter struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Table   string `json:"table"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// AddClientAccounting creates named nft counters and accounting rules for a PPP client.
// Called by RADIUS Acct-Start to start traffic counting for a new session.
func (s *NftService) AddClientAccounting(protocol, ip string) error {
	counterIP := strings.ReplaceAll(ip, ".", "_")
	upCounter := fmt.Sprintf("%s_up_%s", protocol, counterIP)
	downCounter := fmt.Sprintf("%s_down_%s", protocol, counterIP)
	chain := fmt.Sprintf("%s_acct", protocol)

	// Create counters (idempotent)
	s.runCmd("nft", "add", "counter", "ip", "vpn", upCounter)
	s.runCmd("nft", "add", "counter", "ip", "vpn", downCounter)

	// Check if rules already exist for this IP
	output, _ := exec.Command("nft", "list", "chain", "ip", "vpn", chain).Output()
	if !strings.Contains(string(output), "addr "+ip+" ") {
		s.runCmd("nft", "add", "rule", "ip", "vpn", chain, "ip", "saddr", ip, "counter", "name", upCounter)
		s.runCmd("nft", "add", "rule", "ip", "vpn", chain, "ip", "daddr", ip, "counter", "name", downCounter)
	}

	logger.Debugf("nft: added %s accounting for %s", protocol, ip)
	return nil
}

// RemoveClientAccounting removes nft accounting rules and counters for a PPP client.
// Called by RADIUS Acct-Stop to stop traffic counting when a session ends.
func (s *NftService) RemoveClientAccounting(protocol, ip string) error {
	counterIP := strings.ReplaceAll(ip, ".", "_")
	chain := fmt.Sprintf("%s_acct", protocol)

	// Remove rules by handle (find rules matching this IP)
	output, err := exec.Command("nft", "-a", "list", "chain", "ip", "vpn", chain).Output()
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			if strings.Contains(line, "addr "+ip+" ") {
				// Extract handle number
				if idx := strings.Index(line, "# handle "); idx >= 0 {
					handle := strings.TrimSpace(line[idx+9:])
					s.runCmd("nft", "delete", "rule", "ip", "vpn", chain, "handle", handle)
				}
			}
		}
	}

	// Delete counters
	s.runCmd("nft", "delete", "counter", "ip", "vpn", fmt.Sprintf("%s_up_%s", protocol, counterIP))
	s.runCmd("nft", "delete", "counter", "ip", "vpn", fmt.Sprintf("%s_down_%s", protocol, counterIP))

	logger.Debugf("nft: removed %s accounting for %s", protocol, ip)
	return nil
}

// CollectAndResetTraffic atomically reads and resets all VPN traffic counters.
// Uses `nft -j reset counters` for atomic read+reset (no race between read and zero).
// Session maps (IP→email) are provided by the RADIUS service.
// Returns separate L2TP and PPTP client traffic slices.
func (s *NftService) CollectAndResetTraffic(l2tpIPToEmail, pptpIPToEmail, ovpnIPToEmail map[string]string) ([]*xray.ClientTraffic, []*xray.ClientTraffic, []*xray.ClientTraffic) {
	output, err := exec.Command("nft", "-j", "reset", "counters", "table", "ip", "vpn").Output()
	if err != nil {
		return nil, nil, nil
	}

	var result nftCounterOutput
	if err := json.Unmarshal(output, &result); err != nil {
		logger.Debug("nft: failed to parse counter JSON:", err)
		return nil, nil, nil
	}

	// Accumulate per-email traffic
	type trafficPair struct{ up, down int64 }
	l2tpTraffic := make(map[string]*trafficPair)
	pptpTraffic := make(map[string]*trafficPair)
	ovpnTraffic := make(map[string]*trafficPair)

	for _, raw := range result.Nftables {
		var entry nftCounterEntry
		if err := json.Unmarshal(raw, &entry); err != nil || entry.Counter == nil {
			continue
		}
		c := entry.Counter
		if c.Bytes == 0 {
			continue
		}

		// Parse counter name: {protocol}_{direction}_{ip_octets_with_underscores}
		// e.g. "l2tp_up_10_0_2_10" → protocol=l2tp, dir=up, ip=10.0.2.10
		parts := strings.SplitN(c.Name, "_", 3)
		if len(parts) < 3 {
			continue
		}
		protocol := parts[0]  // "l2tp", "pptp", or "openvpn"
		direction := parts[1] // "up" or "down"
		ip := strings.ReplaceAll(parts[2], "_", ".")

		var ipMap map[string]string
		var trafficMap map[string]*trafficPair
		if protocol == "l2tp" {
			ipMap = l2tpIPToEmail
			trafficMap = l2tpTraffic
		} else if protocol == "pptp" {
			ipMap = pptpIPToEmail
			trafficMap = pptpTraffic
		} else if protocol == "openvpn" {
			ipMap = ovpnIPToEmail
			trafficMap = ovpnTraffic
		} else {
			continue
		}

		email, ok := ipMap[ip]
		if !ok {
			continue
		}

		pair := trafficMap[email]
		if pair == nil {
			pair = &trafficPair{}
			trafficMap[email] = pair
		}
		if direction == "up" {
			pair.up += c.Bytes
		} else if direction == "down" {
			pair.down += c.Bytes
		}
	}

	// Convert maps to ClientTraffic slices
	toSlice := func(m map[string]*trafficPair) []*xray.ClientTraffic {
		var result []*xray.ClientTraffic
		for email, pair := range m {
			if pair.up > 0 || pair.down > 0 {
				result = append(result, &xray.ClientTraffic{
					Email: email,
					Up:    pair.up,
					Down:  pair.down,
				})
			}
		}
		return result
	}

	l2tpResult := toSlice(l2tpTraffic)
	pptpResult := toSlice(pptpTraffic)
	ovpnResult := toSlice(ovpnTraffic)

	if len(l2tpResult) > 0 {
		logger.Debugf("nft: collected L2TP traffic for %d client(s)", len(l2tpResult))
	}
	if len(pptpResult) > 0 {
		logger.Debugf("nft: collected PPTP traffic for %d client(s)", len(pptpResult))
	}
	if len(ovpnResult) > 0 {
		logger.Debugf("nft: collected OpenVPN traffic for %d client(s)", len(ovpnResult))
	}

	return l2tpResult, pptpResult, ovpnResult
}

// CleanupLegacyIptables removes old iptables rules left from the pre-nftables implementation.
// All commands are idempotent (silent failure if rules don't exist).
func (s *NftService) CleanupLegacyIptables() {
	// Remove L2TP_ACCT chain
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-F", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-X", "L2TP_ACCT")

	// Remove PPTP_ACCT chain
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-F", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-X", "PPTP_ACCT")

	// Remove old raw L2TP filter
	s.runCmd("iptables", "-D", "INPUT", "-p", "udp", "--dport", "1701",
		"-m", "policy", "--dir", "in", "--pol", "none", "-j", "DROP")

	// Remove old TPROXY rules for all VPN inbounds
	l2tp := L2tpService{}
	pptp := PptpService{}

	l2tpInbounds, _ := l2tp.GetL2tpInbounds()
	for _, inbound := range l2tpInbounds {
		subnet := l2tp.GetSubnetForInbound(inbound)
		port := l2tp.GetTproxyPort(inbound)
		src := fmt.Sprintf("%s.0/24", subnet)
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "tcp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "udp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
	}

	pptpInbounds, _ := pptp.GetPptpInbounds()
	for _, inbound := range pptpInbounds {
		subnet := pptp.GetSubnetForInbound(inbound)
		port := pptp.GetTproxyPort(inbound)
		src := fmt.Sprintf("%s.0/24", subnet)
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "tcp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "udp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
	}

	logger.Info("nft: cleaned up legacy iptables rules")
}

func (s *NftService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("nft: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
