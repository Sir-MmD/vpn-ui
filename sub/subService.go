package sub

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/util/random"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// SubService provides business logic for generating subscription links and managing subscription data.
type SubService struct {
	address     string
	showInfo    bool
	remarkModel string
	datepicker  string
	// scope is the state of the ONE response being rendered: which identities it
	// spans, what each one's real quota is, and which node names have been handed
	// out. Nil on the shared instance the router builds, and set on the per-response
	// copy forResponse returns; every reader of it is nil-safe, so a caller that
	// generates a single link without going through GetSubs (the tests, the panel's
	// own link buttons) keeps working unchanged.
	scope          *subScope
	inboundService service.InboundService
	settingService service.SettingService
	sshService     service.SshService
	wgcService     service.WgcService
	awgService     service.AwgService
	greService     service.GreService
	openvpnService service.OpenVpnService
}

// NewSubService creates a new subscription service with the given configuration.
func NewSubService(showInfo bool, remarkModel string) *SubService {
	return &SubService{
		showInfo:    showInfo,
		remarkModel: remarkModel,
	}
}

// forResponse returns a service scoped to ONE subscription response.
//
// The router builds a single SubService at start-up and every request is served by
// it, while GetSubs writes the caller's host onto it before generating links: two
// subscribers fetching at once can already be handed each other's address. This
// closes that for the request-scoped fields, and more importantly keeps the
// per-response maps in subScope off the shared instance, where a concurrent write
// would panic the process rather than merely return the wrong host.
//
// The protocol services are rebuilt as zero values rather than copied across, and
// that is not a shortcut: nothing ever assigns them (NewSubService sets the two
// display settings and nothing else), so a fresh one is the same object, while
// WgcService, AwgService and GreService each carry a sync.Mutex that must not be
// copied at all. If one of them ever does need configuring, it has to be carried
// here BY POINTER, or the response will quietly render against an unconfigured one.
func (s *SubService) forResponse() *SubService {
	return &SubService{
		address:     s.address,
		showInfo:    s.showInfo,
		remarkModel: s.remarkModel,
		datepicker:  s.datepicker,
		scope:       newSubScope(),
	}
}

// resolveDatepicker returns the calendar the subscriber page renders dates in.
//
// It reads the setting rather than trusting s.datepicker alone because the two
// halves of a page render run on DIFFERENT service instances: the controller calls
// GetSubs (which works on the per-response copy forResponse returns) and then
// BuildPageData on the shared one, so a value stashed on the copy is not there to
// be read back. Answering "gregorian" for a panel configured on the Jalali calendar
// is a silent wrong answer, not a missing one.
func (s *SubService) resolveDatepicker() string {
	if s.datepicker != "" {
		return s.datepicker
	}
	datepicker, err := s.settingService.GetDatepicker()
	if err != nil || datepicker == "" {
		return "gregorian"
	}
	return datepicker
}

// resolveTraffic answers with the traffic figures one membership reports, and says
// where they came from:
//
//   - accountBacked: the row is the ACCOUNT's (quota and expiry from the account,
//     usage from its single client_traffics row), so the header has to count it
//     once however many inbounds serve that account.
//   - exists: there are figures at all. The Show Info suffix is skipped without
//     them, which is what an account that has never been counted gets.
//
// The per-inbound fallback is the legacy path, unchanged, and is what an unmigrated
// panel keeps using.
func (s *SubService) resolveTraffic(inbound *model.Inbound, email string) (traffic xray.ClientTraffic, accountBacked bool, exists bool) {
	if row, ok := s.scope.traffic(email); ok {
		return row, true, true
	}
	row, ok := s.getClientTraffics(inbound.ClientStats, email)
	return row, false, ok
}

// GetSubs retrieves subscription links for a given subscription ID and host.
func (s *SubService) GetSubs(subId string, host string) ([]string, int64, xray.ClientTraffic, error) {
	s = s.forResponse()
	s.address = host
	var result []string
	var traffic xray.ClientTraffic
	usage := newSubUsage()
	inbounds, err := s.getInboundsBySubId(subId)
	if err != nil {
		return nil, 0, traffic, err
	}

	if len(inbounds) == 0 {
		return nil, 0, traffic, common.NewError("No inbounds found with ", subId)
	}

	s.datepicker = s.resolveDatepicker()
	for _, inbound := range inbounds {
		clients, err := s.inboundService.GetClients(inbound)
		if err != nil {
			logger.Error("SubService - GetClients: Unable to get clients from inbound")
		}
		if clients == nil {
			continue
		}
		if len(inbound.Listen) > 0 && inbound.Listen[0] == '@' {
			listen, port, streamSettings, err := s.getFallbackMaster(inbound.Listen, inbound.StreamSettings)
			if err == nil {
				inbound.Listen = listen
				inbound.Port = port
				inbound.StreamSettings = streamSettings
			}
		}
		for _, client := range clients {
			if client.Enable && client.SubID == subId {
				// Count every matching client's usage so the subscriber page shows the
				// account's remaining traffic/days for ALL protocols, including ones with
				// no raw link (wg-c/awg deliver via the Clash sub and gre via the page's
				// config downloads; the credential VPNs add a connection-info line via
				// getLink).
				ct, accountBacked, _ := s.resolveTraffic(inbound, client.Email)
				usage.add(client.Email, ct, accountBacked)
				if link := s.getLink(inbound, client.Email); link != "" {
					result = append(result, link)
				}
			}
		}
	}

	return result, usage.lastOnline, usage.result(), nil
}

// getInboundsBySubId returns every enabled inbound holding a client with this subId.
//
// The protocol list is a maintenance trap worth knowing about: a protocol missing
// from it is invisible to the whole subscription layer (no link, no quota, no page
// entry) with nothing logged, and there is no compile-time tie to model's protocol
// constants to catch the omission.
//
// The JSON_VALID guard is not decoration. SQLite's JSON functions RAISE on
// malformed input rather than returning null, and the cross join evaluates
// JSON_EXTRACT once per inbound row, so a single settings blob that is not valid
// JSON (an ImportDB of a hand-edited backup is the realistic way in) failed this
// query outright and took down EVERY subscription on the panel with a bare
// "Error!", not just the one broken inbound's. Guarding the argument itself rather
// than adding a WHERE term is deliberate: a WHERE term only works while the planner
// happens to evaluate it first.
func (s *SubService) getInboundsBySubId(subId string) ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	// allow "hysteria2" so imports stored with the literal v2 protocol
	// string still surface here (#4081)
	//
	// Ordered by id so the response is stable across refreshes: an account served on
	// several inbounds is rendered in membership order, and the node-name
	// disambiguation in subScope.uniqueName leaves the FIRST claimant's name alone,
	// so an unspecified order would let a subscriber's node names shuffle between
	// polls. SQLite already returns rowid order for this shape; this pins it.
	err := db.Model(model.Inbound{}).Preload("ClientStats").Where(`id in (
		SELECT DISTINCT inbounds.id
		FROM inbounds,
			JSON_EACH(CASE WHEN JSON_VALID(inbounds.settings)
				THEN JSON_EXTRACT(inbounds.settings, '$.clients') ELSE '[]' END) AS client
		WHERE
			protocol in ('vmess','vless','trojan','shadowsocks','hysteria','hysteria2','anytls','tuic','naive','mtproto','ssh','wg-c','awg','gre','openvpn','l2tp','pptp','openconnect','sstp','ikev2')
			AND JSON_EXTRACT(client.value, '$.subId') = ? AND enable = ?
	)`, subId, true).Order("id ASC").Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	return inbounds, nil
}

// getClientTraffics finds an email's row among an inbound's preloaded stats. The
// second return distinguishes "no row" from a row that is genuinely all zeroes,
// which is what decides whether a remark gets a Show Info suffix at all.
func (s *SubService) getClientTraffics(traffics []xray.ClientTraffic, email string) (xray.ClientTraffic, bool) {
	for _, traffic := range traffics {
		if traffic.Email == email {
			return traffic, true
		}
	}
	return xray.ClientTraffic{}, false
}

func (s *SubService) getFallbackMaster(dest string, streamSettings string) (string, int, string, error) {
	db := database.GetDB()
	var inbound *model.Inbound
	err := db.Model(model.Inbound{}).
		Where("JSON_TYPE(settings, '$.fallbacks') = 'array'").
		Where("EXISTS (SELECT * FROM json_each(settings, '$.fallbacks') WHERE json_extract(value, '$.dest') = ?)", dest).
		Find(&inbound).Error
	if err != nil {
		return "", 0, "", err
	}

	var stream map[string]any
	json.Unmarshal([]byte(streamSettings), &stream)
	var masterStream map[string]any
	json.Unmarshal([]byte(inbound.StreamSettings), &masterStream)
	stream["security"] = masterStream["security"]
	stream["tlsSettings"] = masterStream["tlsSettings"]
	stream["externalProxy"] = masterStream["externalProxy"]
	modifiedStream, _ := json.MarshalIndent(stream, "", "  ")

	return inbound.Listen, inbound.Port, string(modifiedStream), nil
}

func (s *SubService) getLink(inbound *model.Inbound, email string) string {
	switch inbound.Protocol {
	case "vmess":
		return s.genVmessLink(inbound, email)
	case "vless":
		return s.genVlessLink(inbound, email)
	case "trojan":
		return s.genTrojanLink(inbound, email)
	case "shadowsocks":
		return s.genShadowsocksLink(inbound, email)
	case "hysteria", "hysteria2":
		return s.genHysteriaLink(inbound, email)
	case "anytls":
		return s.genAnytlsLink(inbound, email)
	case "tuic":
		return s.genTuicLink(inbound, email)
	case "naive":
		return s.genNaiveLink(inbound, email)
	case "mtproto":
		// tg:// is the link Telegram itself imports, but no proxy client can parse it,
		// so the account would contribute nothing a subscription importer recognises.
		// The card is what makes the account appear (with its usage) in those clients.
		return joinLinks(s.genMtprotoLink(inbound, email), s.genConnectionCard(inbound, email))
	case "ssh":
		// Same split: ssh:// here is the Shadowrocket/base64 form (service.sshShareLink),
		// which subscription importers do not read either.
		return joinLinks(s.genSshLink(inbound, email), s.genConnectionCard(inbound, email))
	case "wg-c", "awg":
		// A real, importable link rather than a card: Xray/sing-box clients speak
		// WireGuard, so these accounts get a working entry. The full-fidelity .conf
		// still comes from the Clash sub and the per-client modal.
		return s.genWireguardLink(inbound, email)
	case "openvpn", "l2tp", "pptp", "openconnect", "sstp", "ikev2":
		// Username/password VPNs have no importable proxy URI at all, so the entry is
		// a connection card: parseable enough for a client to accept the account and
		// show its quota, with the credentials in the name.
		return s.genConnectionCard(inbound, email)
	case "gre":
		// No entry at all, deliberately. GRE's peer is a ROUTER: there is no app to paste
		// a URI into, and there is no port for one to name either, since GRE is IP protocol
		// 47 and the inbound's port column only holds a synthetic unique value nothing
		// binds. A card here was therefore a trojan:// link to a dead port, which every
		// client then offered as a connectable node. The account reaches the subscriber
		// through the config-file downloads instead, and its usage still counts towards the
		// page and the Subscription-Userinfo header, which GetSubs accumulates whether or
		// not a link comes out.
		return ""
	}
	return ""
}

// joinLinks joins the per-protocol entries of one account with "\n", the same
// convention genHysteriaLink uses for its external-proxy fan-out (the raw sub endpoint
// splits them back apart), skipping the ones that came out empty.
func joinLinks(links ...string) string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// --- New-protocol raw links: MTProto tg:// and SSH ssh:// ---

// mtprotoModeOrder mirrors MtprotoUser.enabledModes() (web/assets/js/model/inbound.js)
// so the Go and JS links come out in the same order.
var mtprotoModeOrder = []string{"classic", "secure", "tls"}

// mtprotoSecretFor mirrors MtprotoUser.secretFor() byte for byte. The default domain
// is applied BEFORE the trim (JS: (this.tlsDomain||"www.google.com").trim()), so a
// whitespace-only domain yields an empty hex suffix; replicated deliberately.
func mtprotoSecretFor(secret, mode, tlsDomain string) string {
	switch mode {
	case "secure":
		return "dd" + secret
	case "tls":
		domain := tlsDomain
		if domain == "" {
			domain = "www.google.com"
		}
		domain = strings.TrimSpace(domain)
		return "ee" + secret + hex.EncodeToString([]byte(domain)) // lowercase hex == JS padStart(2,"0")
	default:
		return secret
	}
}

// encodeURIComponentGo replicates JS encodeURIComponent. url.QueryEscape is NOT a
// substitute: it escapes ! * ' ( ) and encodes space as '+' rather than %20. Each
// UTF-8 byte is percent-encoded, so walk bytes.
func encodeURIComponentGo(s string) string {
	const keep = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(keep, s[i]) >= 0 {
			b.WriteByte(s[i])
		} else {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
	}
	return b.String()
}

// genMtprotoLink emits one tg://proxy link per enabled mode per endpoint, identical to
// MtprotoUser.links(). The links are "\n"-joined (the same convention genHysteriaLink
// uses for its external-proxy fan-out); the raw sub endpoint splits them back apart.
func (s *SubService) genMtprotoLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.MTPROTO {
		return ""
	}
	clients, _ := s.inboundService.GetClients(inbound)
	idx := findClientIndex(clients, email)
	if idx < 0 {
		return ""
	}
	c := clients[idx]

	// The modes and the FakeTLS domain belong to the INBOUND, not the subscriber's client
	// entry: telemt applies one FakeTLS domain per process and writes its mode map from
	// the inbound's set, so a link built off the old per-client keys would offer
	// transports the proxy refuses. Resolved through the panel's own reader rather than a
	// local struct so an inbound still in the pre-move shape (a restored backup, an API
	// write, the window before the startup lift runs) yields the same links here as the
	// config the daemon is given. Unparseable settings resolve to no mode and no link,
	// which is what a decode error produced before.
	proxy := service.MtprotoInboundPolicyOf(inbound.Settings)

	type endpoint struct {
		host string
		port int
	}
	var endpoints []endpoint
	// Mirror links() EXACTLY: no empty-dest filter, no port fallback. Diverging here
	// would break byte-for-byte parity with the JS-generated links.
	//
	// Three tiers, most specific first. The account's own list wins outright over the
	// inbound's rather than adding to it: both answer "where do this account's links
	// point", so merging would keep handing out the endpoint the operator overrode.
	switch {
	case len(c.ExternalProxy) > 0:
		for _, ep := range c.ExternalProxy {
			endpoints = append(endpoints, endpoint{host: ep.Dest, port: ep.Port})
		}
	case len(proxy.ExternalProxy) > 0:
		for _, ep := range proxy.ExternalProxy {
			endpoints = append(endpoints, endpoint{host: ep.Dest, port: ep.Port})
		}
	default:
		endpoints = append(endpoints, endpoint{host: s.address, port: inbound.Port})
	}

	var links []string
	for _, ep := range endpoints {
		for _, mode := range mtprotoModeOrder {
			if !proxy.ModeEnabled(mode) {
				continue
			}
			links = append(links, "tg://proxy?server="+encodeURIComponentGo(ep.host)+
				"&port="+strconv.Itoa(ep.port)+
				"&secret="+mtprotoSecretFor(c.Secret, mode, proxy.TlsDomain))
		}
	}
	return strings.Join(links, "\n")
}

// genSshLink reuses the SSH service's own config renderer so a subscription entry is
// identical to the per-client config modal by construction (SSH external proxies are
// inbound-level, not on model.Client, so the link cannot be rebuilt from the client).
func (s *SubService) genSshLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.SSH {
		return ""
	}
	cfgs, err := s.sshService.RenderClientConfigs(inbound, email, s.address)
	if err != nil {
		return ""
	}
	links := make([]string, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg.Link != "" {
			links = append(links, cfg.Link)
		}
	}
	return strings.Join(links, "\n")
}

// genConnectionCard produces the subscription entry for the protocols Xray-core has no
// outbound for: the username/password VPNs (l2tp, pptp, openvpn, openconnect, sstp,
// ikev2) plus mtproto and ssh, whose own links (tg://, the base64 ssh://) no
// subscription importer reads.
//
// It is deliberately a `trojan://` URI rather than the plain-text summary this used to
// emit. A subscription client keeps only the lines it can parse, so a plain-text line
// left the account with NO entry: the group imported as empty and the quota/expiry the
// Subscription-Userinfo header carries had nothing to attach to. The card is that entry.
// Its host:port is the real VPN endpoint and its password field the real credential, so
// nothing about it is invented; it simply cannot be dialled by a proxy client, which is
// true of the protocol either way.
//
// The name comes from genRemark, so it carries the same remaining-traffic and
// remaining-days suffixes an Xray node's name gets when Show Info is on, and the
// credentials ride along in it, since the name is all a client displays.
func (s *SubService) genConnectionCard(inbound *model.Inbound, email string) string {
	clients, _ := s.inboundService.GetClients(inbound)
	idx := findClientIndex(clients, email)
	if idx < 0 {
		return ""
	}
	c := clients[idx]

	server := s.address
	if l := strings.TrimSpace(inbound.Listen); l != "" && l != "0.0.0.0" {
		server = l
	}

	// What goes in the URI's credential slot: the account's own secret, so the card
	// carries no filler. ikev2 in psk/eap-tls mode has an email-only account with no
	// password, hence the fallback.
	secret := c.Password
	if inbound.Protocol == model.MTPROTO {
		secret = c.Secret
	}
	if secret == "" {
		secret = email
	}

	// The login name is NOT always the account email. The RADIUS protocols accept
	// either (radius.go matches client.ID or client.Email), but the SSH gateway compares
	// the client id alone (SshService.lookupAccount), so showing the email there would
	// hand the subscriber a username that cannot log in. mtproto has no username at all:
	// the secret IS the credential.
	var settings map[string]any
	_ = json.Unmarshal([]byte(inbound.Settings), &settings)

	protoLabel := protocolLabel(inbound.Protocol)
	if inbound.Protocol == model.L2TP {
		if en, ok := settings["ipsecEnable"].(bool); ok && !en {
			protoLabel = "L2TP"
		}
	}

	details := []string{protoLabel}
	switch inbound.Protocol {
	case model.MTPROTO:
		if c.Secret != "" {
			details = append(details, "secret="+c.Secret)
		}
	case model.SSH:
		details = append(details, "user="+c.ID)
		if c.Password != "" {
			details = append(details, "pass="+c.Password)
		}
	default:
		username := c.ID
		if strings.TrimSpace(username) == "" {
			username = email
		}
		details = append(details, "user="+username)
		if c.Password != "" {
			details = append(details, "pass="+c.Password)
		}
	}

	// The pre-shared key lives at the inbound level for the protocols that use one.
	switch inbound.Protocol {
	case model.L2TP:
		if en, _ := settings["ipsecEnable"].(bool); en {
			if psk, _ := settings["ipsecPsk"].(string); strings.TrimSpace(psk) != "" {
				details = append(details, "psk="+psk)
			}
		}
	case model.IKEV2:
		if mode, _ := settings["authMode"].(string); mode == "psk" {
			if psk, _ := settings["psk"].(string); strings.TrimSpace(psk) != "" {
				details = append(details, "psk="+psk)
			}
		}
	}

	type cardEndpoint struct {
		host   string
		port   int
		remark string
	}
	var endpoints []cardEndpoint

	// Check if externalProxy is defined in inbound.Settings
	if rawEps, ok := settings["externalProxy"].([]any); ok && len(rawEps) > 0 {
		for _, raw := range rawEps {
			if epMap, ok := raw.(map[string]any); ok {
				dest, _ := epMap["dest"].(string)
				dest = strings.TrimSpace(dest)
				if dest == "" {
					continue
				}
				port := 0
				switch p := epMap["port"].(type) {
				case float64:
					port = int(p)
				case int:
					port = p
				}
				if port <= 0 {
					port = inbound.Port
				}
				remark, _ := epMap["remark"].(string)
				endpoints = append(endpoints, cardEndpoint{
					host:   dest,
					port:   port,
					remark: strings.TrimSpace(remark),
				})
			}
		}
	}

	if len(endpoints) == 0 {
		endpoints = append(endpoints, cardEndpoint{
			host: server,
			port: inbound.Port,
		})
	}

	// No query params on purpose: `trojan://secret@host:port#name` is the shape every
	// importer handles, and each extra parameter is one more thing a strict parser can
	// reject. url.URL escapes the credential and the fragment (spaces as %20, not '+',
	// which a fragment must have).
	baseDetails := strings.Join(details, " ")
	cards := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		fullDetails := baseDetails
		if ep.remark != "" {
			fullDetails = baseDetails + " (" + ep.remark + ")"
		}
		u := url.URL{
			Scheme:   "trojan",
			User:     url.User(secret),
			Host:     net.JoinHostPort(ep.host, strconv.Itoa(ep.port)),
			Fragment: s.genRemark(inbound, email, fullDetails),
		}
		cards = append(cards, u.String())
	}
	return strings.Join(cards, "\n")
}

// genWireguardLink emits an importable wireguard:// link per device x endpoint for a wg-c
// or awg account, in the same shape the panel already hands out for native WireGuard
// inbounds (Inbound.getWireguardLink in web/assets/js/model/inbound.js): the client
// private key as the userinfo, the server key/address/mtu as query params. The keys come
// from the protocol service, which is the only thing that holds them.
//
// awg's obfuscation parameters have no place in this URI shape, so an awg link imports as
// plain WireGuard; the Clash sub carries the amnezia-wg-option block for clients that
// support it.
func (s *SubService) genWireguardLink(inbound *model.Inbound, email string) string {
	var params []service.WgcClientParams
	var err error
	switch inbound.Protocol {
	case model.WGC:
		params, err = s.wgcService.RenderClientParams(inbound, email, s.address)
	case model.AWG:
		var awgParams []service.AwgClientParams
		awgParams, err = s.awgService.RenderClientParams(inbound, email, s.address)
		for _, p := range awgParams {
			params = append(params, p.WgcClientParams)
		}
	default:
		return ""
	}
	if err != nil {
		logger.Error("SubService - wireguard RenderClientParams:", err)
		return ""
	}

	links := make([]string, 0, len(params))
	for _, p := range params {
		q := url.Values{}
		q.Set("publickey", p.PublicKey)
		if p.Address != "" {
			q.Set("address", p.Address)
		}
		if p.MTU > 0 {
			q.Set("mtu", strconv.Itoa(p.MTU))
		}
		if p.PreSharedKey != "" {
			q.Set("presharedkey", p.PreSharedKey)
		}
		u := url.URL{
			Scheme:   "wireguard",
			User:     url.User(p.PrivateKey),
			Host:     net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
			RawQuery: q.Encode(),
			Fragment: s.genRemark(inbound, email, p.Name),
		}
		links = append(links, u.String())
	}
	return strings.Join(links, "\n")
}

// protocolLabel is the human-facing name shown on a connection card.
func protocolLabel(p model.Protocol) string {
	switch p {
	case model.OPENVPN:
		return "OpenVPN"
	case model.L2TP:
		return "L2TP/IPsec"
	case model.PPTP:
		return "PPTP"
	case model.IKEV2:
		return "IKEv2"
	case model.OPENCONNECT:
		return "OpenConnect"
	case model.SSTP:
		return "SSTP"
	case model.MTPROTO:
		return "MTProto"
	case model.SSH:
		return "SSH"
	case model.ANYTLS:
		return "AnyTLS"
	case model.TUIC:
		return "TUIC"
	case model.NAIVE:
		return "NaiveProxy"
	}
	return string(p)
}

// Protocol link generators are intentionally ordered as:
// vmess -> vless -> trojan -> shadowsocks -> hysteria.
func (s *SubService) genVmessLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.VMESS {
		return ""
	}
	address := s.resolveInboundAddress(inbound)
	obj := map[string]any{
		"v":    "2",
		"add":  address,
		"port": inbound.Port,
		"type": "none",
	}
	stream := unmarshalStreamSettings(inbound.StreamSettings)
	network, _ := stream["network"].(string)
	applyVmessNetworkParams(stream, network, obj)
	if finalmask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskObj(finalmask, obj)
	}
	security, _ := stream["security"].(string)
	obj["tls"] = security
	if security == "tls" {
		applyVmessTLSParams(stream, obj)
	}

	clients, _ := s.inboundService.GetClients(inbound)
	clientIndex := findClientIndex(clients, email)
	obj["id"] = clients[clientIndex].ID
	obj["scy"] = clients[clientIndex].Security

	externalProxies, _ := stream["externalProxy"].([]any)

	if len(externalProxies) > 0 {
		return s.buildVmessExternalProxyLinks(externalProxies, obj, inbound, email)
	}

	obj["ps"] = s.genRemark(inbound, email, "")
	return buildVmessLink(obj)
}

func (s *SubService) genVlessLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.VLESS {
		return ""
	}
	address := s.resolveInboundAddress(inbound)
	stream := unmarshalStreamSettings(inbound.StreamSettings)
	clients, _ := s.inboundService.GetClients(inbound)
	clientIndex := findClientIndex(clients, email)
	uuid := clients[clientIndex].ID
	port := inbound.Port
	streamNetwork := stream["network"].(string)
	params := make(map[string]string)
	params["type"] = streamNetwork

	// Add encryption parameter for VLESS from inbound settings
	var settings map[string]any
	json.Unmarshal([]byte(inbound.Settings), &settings)
	if encryption, ok := settings["encryption"].(string); ok {
		params["encryption"] = encryption
	}

	applyShareNetworkParams(stream, streamNetwork, params)
	if finalmask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalmask, params)
	}
	security, _ := stream["security"].(string)
	switch security {
	case "tls":
		applyShareTLSParams(stream, params)
		if streamNetwork == "tcp" && len(clients[clientIndex].Flow) > 0 {
			params["flow"] = clients[clientIndex].Flow
		}
	case "reality":
		applyShareRealityParams(stream, params)
		if streamNetwork == "tcp" && len(clients[clientIndex].Flow) > 0 {
			params["flow"] = clients[clientIndex].Flow
		}
	default:
		params["security"] = "none"
	}

	externalProxies, _ := stream["externalProxy"].([]any)

	if len(externalProxies) > 0 {
		return s.buildExternalProxyURLLinks(
			externalProxies,
			params,
			security,
			func(dest string, port int) string {
				return fmt.Sprintf("vless://%s@%s:%d", uuid, dest, port)
			},
			func(ep map[string]any) string {
				return s.genRemark(inbound, email, ep["remark"].(string))
			},
		)
	}

	link := fmt.Sprintf("vless://%s@%s:%d", uuid, address, port)
	return buildLinkWithParams(link, params, s.genRemark(inbound, email, ""))
}

func (s *SubService) genTrojanLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.Trojan {
		return ""
	}
	address := s.resolveInboundAddress(inbound)
	stream := unmarshalStreamSettings(inbound.StreamSettings)
	clients, _ := s.inboundService.GetClients(inbound)
	clientIndex := findClientIndex(clients, email)
	password := clients[clientIndex].Password
	port := inbound.Port
	streamNetwork := stream["network"].(string)
	params := make(map[string]string)
	params["type"] = streamNetwork

	applyShareNetworkParams(stream, streamNetwork, params)
	if finalmask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalmask, params)
	}
	security, _ := stream["security"].(string)
	switch security {
	case "tls":
		applyShareTLSParams(stream, params)
	case "reality":
		applyShareRealityParams(stream, params)
		if streamNetwork == "tcp" && len(clients[clientIndex].Flow) > 0 {
			params["flow"] = clients[clientIndex].Flow
		}
	default:
		params["security"] = "none"
	}

	externalProxies, _ := stream["externalProxy"].([]any)

	if len(externalProxies) > 0 {
		return s.buildExternalProxyURLLinks(
			externalProxies,
			params,
			security,
			func(dest string, port int) string {
				return fmt.Sprintf("trojan://%s@%s:%d", password, dest, port)
			},
			func(ep map[string]any) string {
				return s.genRemark(inbound, email, ep["remark"].(string))
			},
		)
	}

	link := fmt.Sprintf("trojan://%s@%s:%d", password, address, port)
	return buildLinkWithParams(link, params, s.genRemark(inbound, email, ""))
}

func (s *SubService) genShadowsocksLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.Shadowsocks {
		return ""
	}
	address := s.resolveInboundAddress(inbound)
	stream := unmarshalStreamSettings(inbound.StreamSettings)
	clients, _ := s.inboundService.GetClients(inbound)

	var settings map[string]any
	json.Unmarshal([]byte(inbound.Settings), &settings)
	inboundPassword := settings["password"].(string)
	method := settings["method"].(string)
	clientIndex := findClientIndex(clients, email)
	streamNetwork := stream["network"].(string)
	params := make(map[string]string)
	params["type"] = streamNetwork

	applyShareNetworkParams(stream, streamNetwork, params)
	if finalmask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalmask, params)
	}

	security, _ := stream["security"].(string)
	if security == "tls" {
		applyShareTLSParams(stream, params)
	}

	encPart := fmt.Sprintf("%s:%s", method, clients[clientIndex].Password)
	if method[0] == '2' {
		encPart = fmt.Sprintf("%s:%s:%s", method, inboundPassword, clients[clientIndex].Password)
	}

	externalProxies, _ := stream["externalProxy"].([]any)

	if len(externalProxies) > 0 {
		proxyParams := cloneStringMap(params)
		proxyParams["security"] = security
		return s.buildExternalProxyURLLinks(
			externalProxies,
			proxyParams,
			security,
			func(dest string, port int) string {
				return fmt.Sprintf("ss://%s@%s:%d", base64.StdEncoding.EncodeToString([]byte(encPart)), dest, port)
			},
			func(ep map[string]any) string {
				return s.genRemark(inbound, email, ep["remark"].(string))
			},
		)
	}

	link := fmt.Sprintf("ss://%s@%s:%d", base64.StdEncoding.EncodeToString([]byte(encPart)), address, inbound.Port)
	return buildLinkWithParams(link, params, s.genRemark(inbound, email, ""))
}

func (s *SubService) genHysteriaLink(inbound *model.Inbound, email string) string {
	if !model.IsHysteria(inbound.Protocol) {
		return ""
	}
	var stream map[string]any
	json.Unmarshal([]byte(inbound.StreamSettings), &stream)
	clients, _ := s.inboundService.GetClients(inbound)
	clientIndex := -1
	for i, client := range clients {
		if client.Email == email {
			clientIndex = i
			break
		}
	}
	auth := clients[clientIndex].Auth
	params := make(map[string]string)

	params["security"] = "tls"
	tlsSetting, _ := stream["tlsSettings"].(map[string]any)
	alpns, _ := tlsSetting["alpn"].([]any)
	var alpn []string
	for _, a := range alpns {
		alpn = append(alpn, a.(string))
	}
	if len(alpn) > 0 {
		params["alpn"] = strings.Join(alpn, ",")
	}
	if sniValue, ok := searchKey(tlsSetting, "serverName"); ok {
		params["sni"], _ = sniValue.(string)
	}

	tlsSettings, _ := searchKey(tlsSetting, "settings")
	if tlsSetting != nil {
		if fpValue, ok := searchKey(tlsSettings, "fingerprint"); ok {
			params["fp"], _ = fpValue.(string)
		}
		if insecure, ok := searchKey(tlsSettings, "allowInsecure"); ok {
			if insecure.(bool) {
				params["insecure"] = "1"
			}
		}
	}

	// salamander obfs (Hysteria2). The panel-side link generator already
	// emits these; keep the subscription output in sync so a client has
	// the obfs password to match the server.
	if finalmask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalmask, params)
		if udpMasks, ok := finalmask["udp"].([]any); ok {
			for _, m := range udpMasks {
				mask, _ := m.(map[string]any)
				if mask == nil || mask["type"] != "salamander" {
					continue
				}
				settings, _ := mask["settings"].(map[string]any)
				if pw, ok := settings["password"].(string); ok && pw != "" {
					params["obfs"] = "salamander"
					params["obfs-password"] = pw
					break
				}
			}
		}
	}

	var settings map[string]any
	json.Unmarshal([]byte(inbound.Settings), &settings)
	version, _ := settings["version"].(float64)
	protocol := "hysteria2"
	if int(version) == 1 {
		protocol = "hysteria"
	}

	// Fan out one link per External Proxy entry if any. Previously this
	// generator ignored `externalProxy` entirely, so the link kept the
	// server's own IP/port even when the admin configured an alternate
	// endpoint (e.g. a CDN hostname + port that forwards to the node).
	// Matches the behaviour of genVlessLink / genTrojanLink / ….
	externalProxies, _ := stream["externalProxy"].([]any)
	if len(externalProxies) > 0 {
		links := make([]string, 0, len(externalProxies))
		for _, externalProxy := range externalProxies {
			ep, ok := externalProxy.(map[string]any)
			if !ok {
				continue
			}
			dest, _ := ep["dest"].(string)
			portF, okPort := ep["port"].(float64)
			if dest == "" || !okPort {
				continue
			}
			epRemark, _ := ep["remark"].(string)

			link := fmt.Sprintf("%s://%s@%s:%d", protocol, auth, dest, int(portF))
			u, _ := url.Parse(link)
			q := u.Query()
			for k, v := range params {
				q.Add(k, v)
			}
			u.RawQuery = q.Encode()
			u.Fragment = s.genRemark(inbound, email, epRemark)
			links = append(links, u.String())
		}
		return strings.Join(links, "\n")
	}

	// No external proxy configured — fall back to the request host.
	link := fmt.Sprintf("%s://%s@%s:%d", protocol, auth, s.address, inbound.Port)
	url, _ := url.Parse(link)
	q := url.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	url.RawQuery = q.Encode()
	url.Fragment = s.genRemark(inbound, email, "")
	return url.String()
}

// genAnytlsLink emits `anytls://<password>@host:port?<stream params>#<remark>`, the URI
// sing-box, mihomo and the NekoBox family import.
//
// AnyTLS rides Xray's ordinary transport layer, so its query parameters are exactly the
// ones genTrojanLink emits and the External Proxy fan-out behaves identically.
//
// A REALITY inbound still renders `security=reality` here even though mihomo refuses
// that combination outright: the link describes what the server actually runs, and one
// that quietly claimed plain TLS would fail in the handshake with nothing to go on.
func (s *SubService) genAnytlsLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.ANYTLS {
		return ""
	}
	clients, _ := s.inboundService.GetClients(inbound)
	clientIndex := findClientIndex(clients, email)
	if clientIndex < 0 {
		return ""
	}
	address := s.resolveInboundAddress(inbound)
	stream := unmarshalStreamSettings(inbound.StreamSettings)
	// url.User pre-escapes, so a hand-typed password holding a '@' or a ':' still
	// parses. Left raw it would make url.Parse fail, and every caller here ignores
	// that error and dereferences the nil URL.
	userinfo := url.User(clients[clientIndex].Password).String()
	streamNetwork, _ := stream["network"].(string)
	params := make(map[string]string)
	params["type"] = streamNetwork

	applyShareNetworkParams(stream, streamNetwork, params)
	if finalmask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalmask, params)
	}
	security, _ := stream["security"].(string)
	switch security {
	case "tls":
		applyShareTLSParams(stream, params)
	case "reality":
		applyShareRealityParams(stream, params)
	default:
		params["security"] = "none"
	}

	externalProxies, _ := stream["externalProxy"].([]any)
	if len(externalProxies) > 0 {
		return s.buildExternalProxyURLLinks(
			externalProxies,
			params,
			security,
			func(dest string, port int) string {
				return fmt.Sprintf("anytls://%s@%s", userinfo, net.JoinHostPort(dest, strconv.Itoa(port)))
			},
			func(ep map[string]any) string {
				return s.genRemark(inbound, email, ep["remark"].(string))
			},
		)
	}

	link := fmt.Sprintf("anytls://%s@%s", userinfo, net.JoinHostPort(address, strconv.Itoa(inbound.Port)))
	return buildLinkWithParams(link, params, s.genRemark(inbound, email, ""))
}

// genTuicLink emits `tuic://<uuid>:<password>@host:port?...#<remark>`, the URI v2rayN,
// NekoBox and the Rust tuic-client family import.
//
// `alpn=h3` is NOT decoration. The server pins h3, while sing-box, mihomo AND
// tuic-client all default to an EMPTY ALPN list, so a link without it fails the
// handshake with nothing but "tls: no application protocol" to go on.
func (s *SubService) genTuicLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.TUIC {
		return ""
	}
	clients, _ := s.inboundService.GetClients(inbound)
	clientIndex := findClientIndex(clients, email)
	if clientIndex < 0 {
		return ""
	}
	client := clients[clientIndex]
	stream := unmarshalStreamSettings(inbound.StreamSettings)

	var settings map[string]any
	json.Unmarshal([]byte(inbound.Settings), &settings)

	params := map[string]string{
		"alpn":           "h3",
		"udp_relay_mode": "native",
	}
	congestion, _ := settings["congestionControl"].(string)
	if congestion == "" {
		congestion = "cubic"
	}
	params["congestion_control"] = congestion
	applyFixedTLSParams(stream, params)

	userinfo := url.UserPassword(client.ID, client.Password).String()
	return s.buildEndpointLinks(inbound, email, stream, params, func(dest string, port int) string {
		return fmt.Sprintf("tuic://%s@%s", userinfo, net.JoinHostPort(dest, strconv.Itoa(port)))
	})
}

// genNaiveLink emits `naive+https://<username>:<password>@host:port#<remark>`, the
// `--proxy=` string naiveproxy itself takes, prefixed the way NekoBox/NekoRay import it.
//
// naive authenticates with a single `Proxy-Authorization: Basic` header, and the
// username half is the account's `username` when it has one and its EMAIL when it does
// not, matching the core's Validator. url.UserPassword escapes the '@' an email brings,
// without which the URI has two of them and every parser splits it in the wrong place.
//
// The JS twin is genNaiveLink in web/assets/js/model/inbound.js and the two must agree
// byte for byte; TestGenNaiveLinkParity pins it.
//
// The scheme follows the inbound's `network`: tcp is HTTP/2 over TLS, udp is HTTP/3
// over QUIC. An inbound serving both advertises https, which every naive client speaks;
// quic-only is the one case that has to say so.
func (s *SubService) genNaiveLink(inbound *model.Inbound, email string) string {
	if inbound.Protocol != model.NAIVE {
		return ""
	}
	clients, _ := s.inboundService.GetClients(inbound)
	clientIndex := findClientIndex(clients, email)
	if clientIndex < 0 {
		return ""
	}
	stream := unmarshalStreamSettings(inbound.StreamSettings)

	var settings map[string]any
	json.Unmarshal([]byte(inbound.Settings), &settings)
	scheme := "naive+https"
	if network, _ := settings["network"].(string); strings.TrimSpace(network) == "udp" {
		scheme = "naive+quic"
	}

	params := make(map[string]string)
	applyFixedTLSParams(stream, params)

	username := clients[clientIndex].Username
	if username == "" {
		username = email
	}
	userinfo := url.UserPassword(username, clients[clientIndex].Password).String()
	return s.buildEndpointLinks(inbound, email, stream, params, func(dest string, port int) string {
		return fmt.Sprintf("%s://%s@%s", scheme, userinfo, net.JoinHostPort(dest, strconv.Itoa(port)))
	})
}

// applyFixedTLSParams fills in `sni` for the protocols whose TLS is not optional (tuic,
// naive). It deliberately does not emit `security=tls`: there is no other mode for these.
//
// There is deliberately no skip-verification parameter either (tuic's `allow_insecure`,
// naive's `insecure`), and its absence is not an oversight. The panel can no longer
// express it: TlsStreamSettings.Settings in web/assets/js/model/inbound.js carries only
// `fingerprint` and `echConfigList`, and its fromJson rebuilds the object from exactly
// those two, so `allowInsecure` is dropped from any inbound the panel loads and saves.
// The core dropped it too: infra/conf/transport_internet.go hard-errors on it past
// 2026-06-01 and points at pinnedPeerCertSha256 (it never reaches the core from an
// inbound anyway, since web/service/xray.go deletes tlsSettings.settings). Digging it
// out of a legacy DB row here would emit a parameter the browser's generator cannot
// produce, breaking the byte-for-byte agreement between the two generators for exactly
// the operators least equipped to explain the difference.
//
// The consequence worth knowing: a self-signed cert cannot be made to work from the
// panel side. The subscriber must trust or pin it, or the inbound needs a real
// certificate from the bundled acme.sh.
func applyFixedTLSParams(stream map[string]any, params map[string]string) {
	tlsSetting, _ := stream["tlsSettings"].(map[string]any)
	if tlsSetting == nil {
		return
	}
	if sniValue, ok := searchKey(tlsSetting, "serverName"); ok {
		if sni, _ := sniValue.(string); sni != "" {
			params["sni"] = sni
		}
	}
}

// buildEndpointLinks emits one link per External Proxy entry, or a single link for the
// inbound's own address when none is configured, carrying the same query parameters on
// each.
//
// This is deliberately not buildExternalProxyURLLinks. That helper rewrites `security`
// from the entry's forceTls and strips alpn/sni/fp when an entry says "none". TUIC and
// naive have no plaintext mode to force, so honouring forceTls there would drop the
// mandatory alpn=h3 and hand out a link that cannot connect.
func (s *SubService) buildEndpointLinks(
	inbound *model.Inbound,
	email string,
	stream map[string]any,
	params map[string]string,
	makeLink func(dest string, port int) string,
) string {
	externalProxies, _ := stream["externalProxy"].([]any)
	if len(externalProxies) == 0 {
		return buildLinkWithParams(
			makeLink(s.resolveInboundAddress(inbound), inbound.Port),
			params,
			s.genRemark(inbound, email, ""),
		)
	}

	links := make([]string, 0, len(externalProxies))
	for _, externalProxy := range externalProxies {
		ep, ok := externalProxy.(map[string]any)
		if !ok {
			continue
		}
		dest, _ := ep["dest"].(string)
		port, okPort := ep["port"].(float64)
		if dest == "" || !okPort {
			continue
		}
		remark, _ := ep["remark"].(string)
		links = append(links, buildLinkWithParams(
			makeLink(dest, int(port)),
			params,
			s.genRemark(inbound, email, remark),
		))
	}
	return strings.Join(links, "\n")
}

func (s *SubService) resolveInboundAddress(inbound *model.Inbound) string {
	if inbound.Listen == "" || inbound.Listen == "0.0.0.0" || inbound.Listen == "::" || inbound.Listen == "::0" {
		return s.address
	}
	return inbound.Listen
}

func findClientIndex(clients []model.Client, email string) int {
	for i, client := range clients {
		if client.Email == email {
			return i
		}
	}
	return -1
}

func unmarshalStreamSettings(streamSettings string) map[string]any {
	var stream map[string]any
	json.Unmarshal([]byte(streamSettings), &stream)
	return stream
}

func applyPathAndHostParams(settings map[string]any, params map[string]string) {
	params["path"] = settings["path"].(string)
	if host, ok := settings["host"].(string); ok && len(host) > 0 {
		params["host"] = host
	} else {
		headers, _ := settings["headers"].(map[string]any)
		params["host"] = searchHost(headers)
	}
}

func applyPathAndHostObj(settings map[string]any, obj map[string]any) {
	obj["path"] = settings["path"].(string)
	if host, ok := settings["host"].(string); ok && len(host) > 0 {
		obj["host"] = host
	} else {
		headers, _ := settings["headers"].(map[string]any)
		obj["host"] = searchHost(headers)
	}
}

func applyShareNetworkParams(stream map[string]any, streamNetwork string, params map[string]string) {
	switch streamNetwork {
	case "tcp":
		tcp, _ := stream["tcpSettings"].(map[string]any)
		header, _ := tcp["header"].(map[string]any)
		typeStr, _ := header["type"].(string)
		if typeStr == "http" {
			request := header["request"].(map[string]any)
			requestPath, _ := request["path"].([]any)
			params["path"] = requestPath[0].(string)
			headers, _ := request["headers"].(map[string]any)
			params["host"] = searchHost(headers)
			params["headerType"] = "http"
		}
	case "kcp":
		applyKcpShareParams(stream, params)
	case "ws":
		ws, _ := stream["wsSettings"].(map[string]any)
		applyPathAndHostParams(ws, params)
	case "grpc":
		grpc, _ := stream["grpcSettings"].(map[string]any)
		params["serviceName"] = grpc["serviceName"].(string)
		params["authority"], _ = grpc["authority"].(string)
		if grpc["multiMode"].(bool) {
			params["mode"] = "multi"
		}
	case "httpupgrade":
		httpupgrade, _ := stream["httpupgradeSettings"].(map[string]any)
		applyPathAndHostParams(httpupgrade, params)
	case "xhttp":
		xhttp, _ := stream["xhttpSettings"].(map[string]any)
		applyPathAndHostParams(xhttp, params)
		params["mode"], _ = xhttp["mode"].(string)
		applyXhttpShareParams(xhttp, params)
	}
}

// applyXhttpShareObj is the VMess variant of applyXhttpShareParams: VMess
// links are a base64-encoded JSON object, so the fields go straight into that
// JSON instead of into a query string.
func applyXhttpShareObj(xhttp map[string]any, obj map[string]any) {
	for field, value := range collectXhttpShareFields(xhttp) {
		if field == "xPaddingBytes" {
			// The padding range has always ridden along under the flat
			// sing-box style name here; keep it so clients already in the
			// field keep reading it.
			obj["x_padding_bytes"] = value
			continue
		}
		obj[field] = value
	}
}

func applyVmessNetworkParams(stream map[string]any, network string, obj map[string]any) {
	obj["net"] = network
	switch network {
	case "tcp":
		tcp, _ := stream["tcpSettings"].(map[string]any)
		header, _ := tcp["header"].(map[string]any)
		typeStr, _ := header["type"].(string)
		obj["type"] = typeStr
		if typeStr == "http" {
			request := header["request"].(map[string]any)
			requestPath, _ := request["path"].([]any)
			obj["path"] = requestPath[0].(string)
			headers, _ := request["headers"].(map[string]any)
			obj["host"] = searchHost(headers)
		}
	case "kcp":
		applyKcpShareObj(stream, obj)
	case "ws":
		ws, _ := stream["wsSettings"].(map[string]any)
		applyPathAndHostObj(ws, obj)
	case "grpc":
		grpc, _ := stream["grpcSettings"].(map[string]any)
		obj["path"] = grpc["serviceName"].(string)
		obj["authority"] = grpc["authority"].(string)
		if grpc["multiMode"].(bool) {
			obj["type"] = "multi"
		}
	case "httpupgrade":
		httpupgrade, _ := stream["httpupgradeSettings"].(map[string]any)
		applyPathAndHostObj(httpupgrade, obj)
	case "xhttp":
		xhttp, _ := stream["xhttpSettings"].(map[string]any)
		applyPathAndHostObj(xhttp, obj)
		mode, _ := xhttp["mode"].(string)
		obj["mode"] = mode
		// The mode goes out under both names on purpose. This generator has
		// always written it as `mode` (which is also the only name our own
		// vmess importer, Outbound.fromVmessLink, reads), while the panel's
		// copy-link button has always written it as `type` (where v2rayN-family
		// clients read the per-network sub-type). Emitting both is the union of
		// the two shipped behaviours, so the two links finally agree without
		// regressing either client. Left as "none" when the blob carries no
		// mode at all, so a mode-less inbound keeps the link it had.
		if mode != "" {
			obj["type"] = mode
		}
		applyXhttpShareObj(xhttp, obj)
	}
}

func applyShareTLSParams(stream map[string]any, params map[string]string) {
	params["security"] = "tls"
	tlsSetting, _ := stream["tlsSettings"].(map[string]any)
	alpns, _ := tlsSetting["alpn"].([]any)
	var alpn []string
	for _, a := range alpns {
		alpn = append(alpn, a.(string))
	}
	if len(alpn) > 0 {
		params["alpn"] = strings.Join(alpn, ",")
	}
	if sniValue, ok := searchKey(tlsSetting, "serverName"); ok {
		params["sni"], _ = sniValue.(string)
	}

	tlsSettings, _ := searchKey(tlsSetting, "settings")
	if tlsSetting != nil {
		if fpValue, ok := searchKey(tlsSettings, "fingerprint"); ok {
			params["fp"], _ = fpValue.(string)
		}
	}
}

func applyVmessTLSParams(stream map[string]any, obj map[string]any) {
	tlsSetting, _ := stream["tlsSettings"].(map[string]any)
	alpns, _ := tlsSetting["alpn"].([]any)
	if len(alpns) > 0 {
		var alpn []string
		for _, a := range alpns {
			alpn = append(alpn, a.(string))
		}
		obj["alpn"] = strings.Join(alpn, ",")
	}
	if sniValue, ok := searchKey(tlsSetting, "serverName"); ok {
		obj["sni"], _ = sniValue.(string)
	}

	tlsSettings, _ := searchKey(tlsSetting, "settings")
	if tlsSetting != nil {
		if fpValue, ok := searchKey(tlsSettings, "fingerprint"); ok {
			obj["fp"], _ = fpValue.(string)
		}
	}
}

func applyShareRealityParams(stream map[string]any, params map[string]string) {
	params["security"] = "reality"
	realitySetting, _ := stream["realitySettings"].(map[string]any)
	realitySettings, _ := searchKey(realitySetting, "settings")
	if realitySetting != nil {
		if sniValue, ok := searchKey(realitySetting, "serverNames"); ok {
			sNames, _ := sniValue.([]any)
			params["sni"] = sNames[random.Num(len(sNames))].(string)
		}
		if pbkValue, ok := searchKey(realitySettings, "publicKey"); ok {
			params["pbk"], _ = pbkValue.(string)
		}
		if sidValue, ok := searchKey(realitySetting, "shortIds"); ok {
			shortIds, _ := sidValue.([]any)
			params["sid"] = shortIds[random.Num(len(shortIds))].(string)
		}
		if fpValue, ok := searchKey(realitySettings, "fingerprint"); ok {
			if fp, ok := fpValue.(string); ok && len(fp) > 0 {
				params["fp"] = fp
			}
		}
		if pqvValue, ok := searchKey(realitySettings, "mldsa65Verify"); ok {
			if pqv, ok := pqvValue.(string); ok && len(pqv) > 0 {
				params["pqv"] = pqv
			}
		}
		params["spx"] = "/" + random.Seq(15)
	}
}

func buildVmessLink(obj map[string]any) string {
	jsonStr, _ := json.MarshalIndent(obj, "", "  ")
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonStr)
}

func cloneVmessShareObj(baseObj map[string]any, newSecurity string) map[string]any {
	newObj := map[string]any{}
	for key, value := range baseObj {
		if !(newSecurity == "none" && (key == "alpn" || key == "sni" || key == "fp")) {
			newObj[key] = value
		}
	}
	return newObj
}

func (s *SubService) buildVmessExternalProxyLinks(externalProxies []any, baseObj map[string]any, inbound *model.Inbound, email string) string {
	var links strings.Builder
	for index, externalProxy := range externalProxies {
		ep, _ := externalProxy.(map[string]any)
		newSecurity, _ := ep["forceTls"].(string)
		newObj := cloneVmessShareObj(baseObj, newSecurity)
		newObj["ps"] = s.genRemark(inbound, email, ep["remark"].(string))
		newObj["add"] = ep["dest"].(string)
		newObj["port"] = int(ep["port"].(float64))

		if newSecurity != "same" {
			newObj["tls"] = newSecurity
		}
		if index > 0 {
			links.WriteString("\n")
		}
		links.WriteString(buildVmessLink(newObj))
	}
	return links.String()
}

func buildLinkWithParams(link string, params map[string]string, fragment string) string {
	parsedURL, _ := url.Parse(link)
	q := parsedURL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	parsedURL.RawQuery = q.Encode()
	parsedURL.Fragment = fragment
	return parsedURL.String()
}

func buildLinkWithParamsAndSecurity(link string, params map[string]string, fragment, security string, omitTLSFields bool) string {
	parsedURL, _ := url.Parse(link)
	q := parsedURL.Query()
	for k, v := range params {
		if k == "security" {
			v = security
		}
		if omitTLSFields && (k == "alpn" || k == "sni" || k == "fp") {
			continue
		}
		q.Add(k, v)
	}
	parsedURL.RawQuery = q.Encode()
	parsedURL.Fragment = fragment
	return parsedURL.String()
}

func (s *SubService) buildExternalProxyURLLinks(
	externalProxies []any,
	params map[string]string,
	baseSecurity string,
	makeLink func(dest string, port int) string,
	makeRemark func(ep map[string]any) string,
) string {
	links := make([]string, 0, len(externalProxies))
	for _, externalProxy := range externalProxies {
		ep, _ := externalProxy.(map[string]any)
		newSecurity, _ := ep["forceTls"].(string)
		dest, _ := ep["dest"].(string)
		port := int(ep["port"].(float64))

		securityToApply := baseSecurity
		if newSecurity != "same" {
			securityToApply = newSecurity
		}

		links = append(
			links,
			buildLinkWithParamsAndSecurity(
				makeLink(dest, port),
				params,
				makeRemark(ep),
				securityToApply,
				newSecurity == "none",
			),
		)
	}
	return strings.Join(links, "\n")
}

func cloneStringMap(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	maps.Copy(cloned, source)
	return cloned
}

// genRemark composes the node name a client displays: the inbound remark, the
// email and a per-protocol extra, in the operator's configured order, plus the
// remaining traffic and days when Show Info is on.
//
// Any of the three parts can be empty and the order is configurable (the panel lets
// the inbound remark be dropped entirely), so the name is NOT guaranteed to
// distinguish two memberships of one account on its own. That is why every exit
// runs through subScope.uniqueName rather than the composition trying to be unique
// by construction.
func (s *SubService) genRemark(inbound *model.Inbound, email string, extra string) string {
	separationChar := string(s.remarkModel[0])
	orderChars := s.remarkModel[1:]
	orders := map[byte]string{
		'i': "",
		'e': "",
		'o': "",
	}
	if len(email) > 0 {
		orders['e'] = email
	}
	if len(inbound.Remark) > 0 {
		orders['i'] = inbound.Remark
	}
	if len(extra) > 0 {
		orders['o'] = extra
	}

	var remark []string
	for i := 0; i < len(orderChars); i++ {
		char := orderChars[i]
		order, exists := orders[char]
		if exists && order != "" {
			remark = append(remark, order)
		}
	}

	if s.showInfo {
		// The account's own figures when it has an account, this inbound's preloaded
		// row otherwise. Reading the preload alone is what left an account served on
		// three inbounds showing its remaining traffic and days on ONE node and
		// nothing on the other two, since its single client_traffics row can only
		// name one of them.
		stats, _, statsExist := s.resolveTraffic(inbound, email)

		// Get remained days
		if statsExist {
			if !stats.Enable {
				return s.scope.uniqueName(fmt.Sprintf("⛔️N/A%s%s", separationChar, strings.Join(remark, separationChar)), inbound, separationChar)
			}
			if vol := stats.Total - (stats.Up + stats.Down); vol > 0 {
				remark = append(remark, fmt.Sprintf("%s%s", common.FormatTraffic(vol), "📊"))
			}
			now := time.Now().Unix()
			switch exp := stats.ExpiryTime / 1000; {
			case exp > 0:
				remainingSeconds := exp - now
				days := remainingSeconds / 86400
				hours := (remainingSeconds % 86400) / 3600
				minutes := (remainingSeconds % 3600) / 60
				if days > 0 {
					if hours > 0 {
						remark = append(remark, fmt.Sprintf("%dD,%dH⏳", days, hours))
					} else {
						remark = append(remark, fmt.Sprintf("%dD⏳", days))
					}
				} else if hours > 0 {
					remark = append(remark, fmt.Sprintf("%dH⏳", hours))
				} else {
					remark = append(remark, fmt.Sprintf("%dM⏳", minutes))
				}
			case exp < 0:
				days := exp / -86400
				hours := (exp % -86400) / 3600
				minutes := (exp % -3600) / 60
				if days > 0 {
					if hours > 0 {
						remark = append(remark, fmt.Sprintf("%dD,%dH⏳", days, hours))
					} else {
						remark = append(remark, fmt.Sprintf("%dD⏳", days))
					}
				} else if hours > 0 {
					remark = append(remark, fmt.Sprintf("%dH⏳", hours))
				} else {
					remark = append(remark, fmt.Sprintf("%dM⏳", minutes))
				}
			}
		}
	}
	// Every exit goes through the namer: a node name that collides with one already
	// handed out in this response would REPLACE it in the client. See uniqueName.
	return s.scope.uniqueName(strings.Join(remark, separationChar), inbound, separationChar)
}

func searchKey(data any, key string) (any, bool) {
	switch val := data.(type) {
	case map[string]any:
		for k, v := range val {
			if k == key {
				return v, true
			}
			if result, ok := searchKey(v, key); ok {
				return result, true
			}
		}
	case []any:
		for _, v := range val {
			if result, ok := searchKey(v, key); ok {
				return result, true
			}
		}
	}
	return nil, false
}

// xhttpModeledKeys are the xhttpSettings keys the panel form models
// structurally. Anything else in the blob (a hand edit, xray's own nested
// `extra` object, a key from a newer core) is passed through to the client
// verbatim. Mirrors xHTTPStreamSettings.STRUCTURED_KEYS in
// web/assets/js/model/inbound.js.
var xhttpModeledKeys = map[string]struct{}{
	"path": {}, "host": {}, "headers": {}, "scMaxBufferedPosts": {},
	"scMaxEachPostBytes": {}, "scStreamUpServerSecs": {}, "noSSEHeader": {},
	"xPaddingBytes": {}, "mode": {}, "xPaddingObfsMode": {}, "xPaddingKey": {},
	"xPaddingHeader": {}, "xPaddingPlacement": {}, "xPaddingMethod": {},
	"uplinkHTTPMethod": {}, "sessionPlacement": {}, "sessionKey": {},
	"seqPlacement": {}, "seqKey": {}, "uplinkDataPlacement": {},
	"uplinkDataKey": {}, "uplinkChunkSize": {}, "noGRPCHeader": {},
	"scMinPostsIntervalMs": {}, "serverMaxHeaderBytes": {}, "xmux": {},
	"downloadSettings": {},
}

// xhttpShareDefaults is the value the xhttp form starts each field on. A share
// link only carries a field once the admin has actually moved it off this
// default: a stock xhttp inbound has to keep producing a short link (QR codes
// stop being scannable fast) and links handed out before this existed must not
// change.
//
// Numbers are float64 because these come out of encoding/json, so a value that
// is a string in the stored blob never compares equal to a numeric default and
// is (correctly) shared. Mirrors XHTTP_SHARE_DEFAULTS in inbound.js.
//
// SCALARS ONLY. The values here are compared against whatever the stored blob
// holds, and comparing two `any` values that both carry the same uncomparable
// dynamic type (a map, a slice) panics at runtime, which would take the whole
// subscription endpoint down. xmux and downloadSettings are objects and are
// therefore handled explicitly in collectXhttpShareFields, not from this table.
var xhttpShareDefaults = map[string]any{
	"scMaxBufferedPosts":   float64(30),
	"scMaxEachPostBytes":   "1000000",
	"scStreamUpServerSecs": "20-80",
	"uplinkChunkSize":      float64(0),
	"scMinPostsIntervalMs": "30",
	"serverMaxHeaderBytes": float64(0),
}

// xhttpShareFields are the plain scalar xhttp settings copied through as-is
// once they differ from xhttpShareDefaults (no default means "skip when
// empty"). The xPadding* / headers / noSSEHeader / noGRPCHeader fields need
// shaping and xmux / downloadSettings are objects, so collectXhttpShareFields
// handles all of those explicitly instead.
var xhttpShareFields = []string{
	"scMaxBufferedPosts", "scMaxEachPostBytes", "scStreamUpServerSecs",
	"uplinkHTTPMethod", "sessionPlacement", "sessionKey", "seqPlacement",
	"seqKey", "uplinkDataPlacement", "uplinkDataKey", "uplinkChunkSize",
	"scMinPostsIntervalMs", "serverMaxHeaderBytes",
}

// xhttpXmuxDefaults are xray's own xmux defaults, which are also what both
// panel forms start on. Mirrors XHTTP_XMUX_DEFAULTS in
// web/assets/js/model/inbound.js; the numbers are float64 for the same reason
// as in xhttpShareDefaults (they arrive through encoding/json).
var xhttpXmuxDefaults = map[string]any{
	"maxConcurrency":   "16-32",
	"maxConnections":   float64(0),
	"cMaxReuseTimes":   float64(0),
	"hMaxRequestTimes": "600-900",
	"hMaxReusableSecs": "1800-3000",
	"hKeepAlivePeriod": float64(0),
}

// normalizeXhttpXmux fills in every xmux key the stored blob left out, so the
// client is handed the same six values the panel form shows.
//
// A key that is PRESENT but empty is kept as-is rather than pushed back to the
// default. The core reads an empty Int32Range as 0 (ParseRangeString treats ""
// as zero, it does not reject it), and 0 is the only way to say "this strategy
// is off": clearing maxConcurrency is exactly how an admin switches to the
// maxConnections strategy, and the two settings are mutually exclusive. Unknown
// sub-keys (a newer core's cMaxLifetimeMs, a hand edit) ride along untouched.
//
// Mirrors xHTTPStreamSettings.normalizeXmux in web/assets/js/model/inbound.js.
func normalizeXhttpXmux(raw any) map[string]any {
	out := make(map[string]any, len(xhttpXmuxDefaults))
	for key, value := range xhttpXmuxDefaults {
		out[key] = value
	}
	src, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	for key, value := range src {
		if value == nil {
			continue
		}
		out[key] = value
	}
	return out
}

// normalizeXhttpDownloadSettings reduces downloadSettings to "a non-empty JSON
// object, or nothing". A null, a scalar, an array or an empty object all mean
// not set, and the key then has to be omitted entirely rather than shared
// empty: xray builds a whole StreamConfig out of whatever is there, and an
// empty one is not the same thing as none. Mirrors
// xHTTPStreamSettings.normalizeDownloadSettings in inbound.js.
func normalizeXhttpDownloadSettings(raw any) map[string]any {
	obj, ok := raw.(map[string]any)
	if !ok || len(obj) == 0 {
		return nil
	}
	return obj
}

// collectXhttpShareFields gathers every xhttp setting a client has to match
// the server on, minus path / host / mode which the link already carries as
// its own top-level params.
//
// An xhttp client that guesses any of these wrong does not degrade, it fails.
// Before this existed only path / host / mode plus the xPadding* subset were
// propagated, so a server configured with a custom session/seq/uplink
// placement, an uplink HTTP method or extra headers silently diverged from the
// client: the client kept xray's defaults, hit the server and was rejected
// (the padding case logs "invalid padding" on the inbound; the client-visible
// symptom was "xhttp doesn't connect").
//
// Mirrored on the JS side by Inbound.collectXhttpShareFields in
// web/assets/js/model/inbound.js. The two generators have to agree key for
// key, because the panel's copy-link button and the subscription URL must not
// hand out two different configs for one inbound.
func collectXhttpShareFields(xhttp map[string]any) map[string]any {
	out := map[string]any{}
	if xhttp == nil {
		return out
	}

	// Unmodeled keys ride through verbatim.
	for key, value := range xhttp {
		if _, modeled := xhttpModeledKeys[key]; modeled {
			continue
		}
		out[key] = value
	}

	// xPaddingBytes is emitted even when it still holds the panel default,
	// which is what this generator has always done. Clients already in the
	// field read it, so narrowing it now would break working links.
	if xpb, ok := xhttp["xPaddingBytes"].(string); ok && len(xpb) > 0 {
		out["xPaddingBytes"] = xpb
	}
	if obfs, ok := xhttp["xPaddingObfsMode"].(bool); ok && obfs {
		out["xPaddingObfsMode"] = true
		// The obfs-mode-only fields: only populate the ones the admin
		// actually set, so xray-core falls back to its own defaults for
		// the rest instead of seeing spurious empty strings.
		for _, field := range []string{"xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod"} {
			if v, ok := xhttp[field].(string); ok && len(v) > 0 {
				out[field] = v
			}
		}
	}

	if headers := normalizeXhttpHeaders(xhttp["headers"]); len(headers) > 0 {
		out["headers"] = headers
	}
	if noSSE, ok := xhttp["noSSEHeader"].(bool); ok && noSSE {
		out["noSSEHeader"] = true
	}
	if noGRPC, ok := xhttp["noGRPCHeader"].(bool); ok && noGRPC {
		out["noGRPCHeader"] = true
	}

	for _, field := range xhttpShareFields {
		value, present := xhttp[field]
		if !present || value == nil {
			continue
		}
		if s, isStr := value.(string); isStr && s == "" {
			continue
		}
		// reflect.DeepEqual and not ==: comparing two `any` values panics at
		// runtime when both hold the same uncomparable dynamic type, and the
		// values on the left come straight out of a stored blob that anyone
		// with panel access can hand-edit into a map or a slice. A panic here
		// takes the subscription endpoint down for every client, not just the
		// one inbound, so the comparison has to be one that cannot panic.
		if def, hasDefault := xhttpShareDefaults[field]; hasDefault && reflect.DeepEqual(value, def) {
			continue
		}
		out[field] = value
	}

	// xmux and downloadSettings are objects, so they stay out of the scalar
	// loop above and out of xhttpShareDefaults entirely (see the note there).
	//
	// xmux goes on the wire only once the admin has moved a knob off the stock
	// set, and then it goes whole: a partial xmux would leave the client
	// filling the gaps from its own defaults, which is the exact kind of silent
	// server/client divergence this function exists to prevent.
	if xmux := normalizeXhttpXmux(xhttp["xmux"]); !reflect.DeepEqual(xmux, xhttpXmuxDefaults) {
		out["xmux"] = xmux
	}

	// downloadSettings has no default at all, so it rides verbatim whenever it
	// is set. Except in stream-one mode, where the core rejects it outright
	// (transport_internet.go: `Can not use "downloadSettings" in "stream-one"
	// mode.`) and rejects the entire config with it. The panel will not save
	// that combination, but a blob hand-edited outside the panel can still hold
	// it, and a link no client can build is worse than a link that quietly
	// drops one key.
	if download := normalizeXhttpDownloadSettings(xhttp["downloadSettings"]); download != nil {
		if mode, _ := xhttp["mode"].(string); mode != "stream-one" {
			out["downloadSettings"] = download
		}
	}

	return out
}

// normalizeXhttpHeaders flattens a stored headers map to the name -> single
// string shape xray expects on the client side. The panel always writes that
// shape, but an imported or hand-edited inbound can carry the multi-value
// name -> [v1, v2] form; the panel form collapses that to the last value when
// it loads (XrayCommonClass.toV2Headers), so do the same here rather than let
// the two generators disagree. Entries with an empty name or value are
// dropped, again matching toV2Headers.
func normalizeXhttpHeaders(raw any) map[string]any {
	headers, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(headers))
	for name, value := range headers {
		if name == "" {
			continue
		}
		switch v := value.(type) {
		case string:
			if v != "" {
				out[name] = v
			}
		case []any:
			if len(v) == 0 {
				continue
			}
			if last, isStr := v[len(v)-1].(string); isStr && last != "" {
				out[name] = last
			}
		}
	}
	return out
}

// applyXhttpShareParams writes the xhttp settings into the URL query params of
// a vless:// / trojan:// / ss:// link. Two encodings are used so every popular
// client can read at least one:
//
//   - x_padding_bytes=<range>  flat param, understood by sing-box and its
//     derivatives (Podkop, OpenWRT sing-box, Karing, NekoBox) which never
//     look inside `extra`.
//   - extra=<url-encoded-json> the whole xhttp object, which is how xray-core
//     clients (v2rayNG, Happ, Furious, Exclave) pick it up.
func applyXhttpShareParams(xhttp map[string]any, params map[string]string) {
	if xhttp == nil {
		return
	}

	if xpb, ok := xhttp["xPaddingBytes"].(string); ok && len(xpb) > 0 {
		params["x_padding_bytes"] = xpb
	}

	extra := collectXhttpShareFields(xhttp)
	if len(extra) > 0 {
		if b, err := marshalShareJSON(extra); err == nil {
			params["extra"] = string(b)
		}
	}
}

// marshalShareJSON writes JSON the way JavaScript's JSON.stringify does.
// encoding/json escapes the three HTML-significant characters (less-than,
// greater-than, ampersand) into their \u form by default, which would make
// this blob differ byte for byte from the one the panel's copy-link button
// builds for the very same inbound. One header value carrying an ampersand
// is enough to trigger it.
func marshalShareJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

var kcpMaskToHeaderType = map[string]string{
	"header-dns":       "dns",
	"header-dtls":      "dtls",
	"header-srtp":      "srtp",
	"header-utp":       "utp",
	"header-wechat":    "wechat-video",
	"header-wireguard": "wireguard",
}

var validFinalMaskUDPTypes = map[string]struct{}{
	"salamander":       {},
	"mkcp-aes128gcm":   {},
	"header-dns":       {},
	"header-dtls":      {},
	"header-srtp":      {},
	"header-utp":       {},
	"header-wechat":    {},
	"header-wireguard": {},
	"mkcp-original":    {},
	"xdns":             {},
	"xicmp":            {},
	"noise":            {},
	"header-custom":    {},
}

var validFinalMaskTCPTypes = map[string]struct{}{
	"header-custom": {},
	"fragment":      {},
	"sudoku":        {},
}

// applyKcpShareParams reconstructs legacy KCP share-link fields from either
// the historical kcpSettings.header/seed shape or the current finalmask model.
// This keeps subscription output compatible while avoiding panics when older
// keys are absent from modern inbounds.
func applyKcpShareParams(stream map[string]any, params map[string]string) {
	extractKcpShareFields(stream).applyToParams(params)
}

func applyKcpShareObj(stream map[string]any, obj map[string]any) {
	extractKcpShareFields(stream).applyToObj(obj)
}

type kcpShareFields struct {
	headerType string
	seed       string
	mtu        int
	tti        int
}

func (f kcpShareFields) applyToParams(params map[string]string) {
	if f.headerType != "" && f.headerType != "none" {
		params["headerType"] = f.headerType
	}
	setStringParam(params, "seed", f.seed)
	setIntParam(params, "mtu", f.mtu)
	setIntParam(params, "tti", f.tti)
}

func (f kcpShareFields) applyToObj(obj map[string]any) {
	if f.headerType != "" && f.headerType != "none" {
		obj["type"] = f.headerType
	}
	setStringField(obj, "path", f.seed)
	setIntField(obj, "mtu", f.mtu)
	setIntField(obj, "tti", f.tti)
}

func extractKcpShareFields(stream map[string]any) kcpShareFields {
	fields := kcpShareFields{headerType: "none"}

	if kcp, ok := stream["kcpSettings"].(map[string]any); ok {
		if header, ok := kcp["header"].(map[string]any); ok {
			if value, ok := header["type"].(string); ok && value != "" {
				fields.headerType = value
			}
		}
		if value, ok := kcp["seed"].(string); ok && value != "" {
			fields.seed = value
		}
		if value, ok := readPositiveInt(kcp["mtu"]); ok {
			fields.mtu = value
		}
		if value, ok := readPositiveInt(kcp["tti"]); ok {
			fields.tti = value
		}
	}

	for _, rawMask := range normalizedFinalMaskUDPMasks(stream["finalmask"]) {
		mask, _ := rawMask.(map[string]any)
		if mask == nil {
			continue
		}
		maskType, _ := mask["type"].(string)
		if mapped, ok := kcpMaskToHeaderType[maskType]; ok {
			fields.headerType = mapped
			continue
		}

		switch maskType {
		case "mkcp-original":
			fields.seed = ""
		case "mkcp-aes128gcm":
			fields.seed = ""
			settings, _ := mask["settings"].(map[string]any)
			if value, ok := settings["password"].(string); ok && value != "" {
				fields.seed = value
			}
		}
	}

	return fields
}

func readPositiveInt(value any) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, number > 0
	case int32:
		return int(number), number > 0
	case int64:
		return int(number), number > 0
	case float32:
		parsed := int(number)
		return parsed, parsed > 0
	case float64:
		parsed := int(number)
		return parsed, parsed > 0
	default:
		return 0, false
	}
}

func setStringParam(params map[string]string, key, value string) {
	if value == "" {
		delete(params, key)
		return
	}
	params[key] = value
}

func setIntParam(params map[string]string, key string, value int) {
	if value <= 0 {
		delete(params, key)
		return
	}
	params[key] = fmt.Sprintf("%d", value)
}

func setStringField(obj map[string]any, key, value string) {
	if value == "" {
		delete(obj, key)
		return
	}
	obj[key] = value
}

func setIntField(obj map[string]any, key string, value int) {
	if value <= 0 {
		delete(obj, key)
		return
	}
	obj[key] = value
}

// applyFinalMaskParams exports the finalmask payload as the compact
// `fm=<json>` share-link field used by v2rayN-compatible clients.
func applyFinalMaskParams(finalmask map[string]any, params map[string]string) {
	if fm, ok := marshalFinalMask(finalmask); ok {
		params["fm"] = fm
	}
}

func applyFinalMaskObj(finalmask map[string]any, obj map[string]any) {
	if fm, ok := marshalFinalMask(finalmask); ok {
		obj["fm"] = fm
	}
}

func marshalFinalMask(finalmask map[string]any) (string, bool) {
	normalized := normalizeFinalMask(finalmask)
	if !hasFinalMaskContent(normalized) {
		return "", false
	}
	b, err := json.Marshal(normalized)
	if err != nil || len(b) == 0 || string(b) == "null" {
		return "", false
	}
	return string(b), true
}

func normalizeFinalMask(finalmask map[string]any) map[string]any {
	tcpMasks := normalizedFinalMaskTCPMasks(finalmask)
	udpMasks := normalizedFinalMaskUDPMasks(finalmask)
	quicParams, hasQuicParams := finalmask["quicParams"].(map[string]any)

	if len(tcpMasks) == 0 && len(udpMasks) == 0 && !hasQuicParams {
		return nil
	}

	result := map[string]any{}
	if len(tcpMasks) > 0 {
		result["tcp"] = tcpMasks
	}
	if len(udpMasks) > 0 {
		result["udp"] = udpMasks
	}
	if hasQuicParams && len(quicParams) > 0 {
		result["quicParams"] = quicParams
	}
	return result
}

func normalizedFinalMaskTCPMasks(value any) []any {
	finalmask, _ := value.(map[string]any)
	if finalmask == nil {
		return nil
	}
	rawMasks, _ := finalmask["tcp"].([]any)
	if len(rawMasks) == 0 {
		return nil
	}

	normalized := make([]any, 0, len(rawMasks))
	for _, rawMask := range rawMasks {
		mask, _ := rawMask.(map[string]any)
		if mask == nil {
			continue
		}
		maskType, _ := mask["type"].(string)
		if _, ok := validFinalMaskTCPTypes[maskType]; !ok || maskType == "" {
			continue
		}

		normalizedMask := map[string]any{"type": maskType}
		if settings, ok := mask["settings"].(map[string]any); ok && len(settings) > 0 {
			normalizedMask["settings"] = settings
		}
		normalized = append(normalized, normalizedMask)
	}

	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizedFinalMaskUDPMasks(value any) []any {
	finalmask, _ := value.(map[string]any)
	if finalmask == nil {
		return nil
	}
	rawMasks, _ := finalmask["udp"].([]any)
	if len(rawMasks) == 0 {
		return nil
	}

	normalized := make([]any, 0, len(rawMasks))
	for _, rawMask := range rawMasks {
		mask, _ := rawMask.(map[string]any)
		if mask == nil {
			continue
		}
		maskType, _ := mask["type"].(string)
		if _, ok := validFinalMaskUDPTypes[maskType]; !ok || maskType == "" {
			continue
		}

		normalizedMask := map[string]any{"type": maskType}
		if settings, ok := mask["settings"].(map[string]any); ok && len(settings) > 0 {
			normalizedMask["settings"] = settings
		}
		normalized = append(normalized, normalizedMask)
	}

	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func hasFinalMaskContent(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return len(v) > 0
	case map[string]any:
		for _, item := range v {
			if hasFinalMaskContent(item) {
				return true
			}
		}
		return false
	case []any:
		return slices.ContainsFunc(v, hasFinalMaskContent)
	default:
		return true
	}
}

func searchHost(headers any) string {
	data, _ := headers.(map[string]any)
	for k, v := range data {
		if strings.EqualFold(k, "host") {
			switch v.(type) {
			case []any:
				hosts, _ := v.([]any)
				if len(hosts) > 0 {
					return hosts[0].(string)
				} else {
					return ""
				}
			case any:
				return v.(string)
			}
		}
	}

	return ""
}

// PageData is a view model for subpage.html
// PageData contains data for rendering the subscription information page.
type PageData struct {
	Host         string
	BasePath     string
	SId          string
	Download     string
	Upload       string
	Total        string
	Used         string
	Remained     string
	Expire       int64
	LastOnline   int64
	Datepicker   string
	DownloadByte int64
	UploadByte   int64
	TotalByte    int64
	SubUrl       string
	SubJsonUrl   string
	SubClashUrl  string
	Result       []string
	Configs      []SubConfigLink
}

// ResolveRequest extracts scheme and host info from request/headers consistently.
// ResolveRequest extracts scheme, host, and header information from an HTTP request.
func (s *SubService) ResolveRequest(c *gin.Context) (scheme string, host string, hostWithPort string, hostHeader string) {
	// scheme
	scheme = "http"
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}

	// base host (no port)
	if h, err := getHostFromXFH(c.GetHeader("X-Forwarded-Host")); err == nil && h != "" {
		host = h
	}
	if host == "" {
		var err error
		host, _, err = net.SplitHostPort(c.Request.Host)
		if err != nil {
			host = c.Request.Host
		}
	}
	if host == "" {
		host = c.GetHeader("X-Real-IP")
	}

	// host:port for URLs
	hostWithPort = c.GetHeader("X-Forwarded-Host")
	if hostWithPort == "" {
		hostWithPort = c.Request.Host
	}
	if hostWithPort == "" {
		hostWithPort = host
	}

	// header display host
	hostHeader = c.GetHeader("X-Forwarded-Host")
	if hostHeader == "" {
		hostHeader = c.Request.Host
	}
	if hostHeader == "" {
		hostHeader = host
	}
	return
}

// BuildURLs constructs absolute subscription and JSON subscription URLs for a given subscription ID.
// It prioritizes configured URIs, then individual settings, and finally falls back to request-derived components.
func (s *SubService) BuildURLs(scheme, hostWithPort, subPath, subJsonPath, subClashPath, subId string) (subURL, subJsonURL, subClashURL string) {
	if subId == "" {
		return "", "", ""
	}

	configuredSubURI, _ := s.settingService.GetSubURI()
	configuredSubJsonURI, _ := s.settingService.GetSubJsonURI()
	configuredSubClashURI, _ := s.settingService.GetSubClashURI()

	var baseScheme, baseHostWithPort string
	if configuredSubURI == "" || configuredSubJsonURI == "" || configuredSubClashURI == "" {
		baseScheme, baseHostWithPort = s.getBaseSchemeAndHost(scheme, hostWithPort)
	}

	subURL = s.buildSingleURL(configuredSubURI, baseScheme, baseHostWithPort, subPath, subId)
	subJsonURL = s.buildSingleURL(configuredSubJsonURI, baseScheme, baseHostWithPort, subJsonPath, subId)
	subClashURL = s.buildSingleURL(configuredSubClashURI, baseScheme, baseHostWithPort, subClashPath, subId)

	return subURL, subJsonURL, subClashURL
}

// getBaseSchemeAndHost determines the base scheme and host from settings or falls back to request values
func (s *SubService) getBaseSchemeAndHost(requestScheme, requestHostWithPort string) (string, string) {
	subDomain, err := s.settingService.GetSubDomain()
	if err != nil || subDomain == "" {
		return requestScheme, requestHostWithPort
	}

	// Get port and TLS settings
	subPort, _ := s.settingService.GetSubPort()
	subKeyFile, _ := s.settingService.GetSubKeyFile()
	subCertFile, _ := s.settingService.GetSubCertFile()

	// Determine scheme from TLS configuration
	scheme := "http"
	if subKeyFile != "" && subCertFile != "" {
		scheme = "https"
	}

	// Build host:port, always include port for clarity
	hostWithPort := fmt.Sprintf("%s:%d", subDomain, subPort)

	return scheme, hostWithPort
}

// buildSingleURL constructs a single URL using configured URI or base components
func (s *SubService) buildSingleURL(configuredURI, baseScheme, baseHostWithPort, basePath, subId string) string {
	if configuredURI != "" {
		return s.joinPathWithID(configuredURI, subId)
	}

	baseURL := fmt.Sprintf("%s://%s", baseScheme, baseHostWithPort)
	return s.joinPathWithID(baseURL+basePath, subId)
}

// joinPathWithID safely joins a base path with a subscription ID
func (s *SubService) joinPathWithID(basePath, subId string) string {
	if strings.HasSuffix(basePath, "/") {
		return basePath + subId
	}
	return basePath + "/" + subId
}

// BuildPageData parses header and prepares the template view model.
// BuildPageData constructs page data for rendering the subscription information page.
func (s *SubService) BuildPageData(subId string, hostHeader string, traffic xray.ClientTraffic, lastOnline int64, subs []string, subURL, subJsonURL, subClashURL string, basePath string) PageData {
	download := common.FormatTraffic(traffic.Down)
	upload := common.FormatTraffic(traffic.Up)
	total := "∞"
	used := common.FormatTraffic(traffic.Up + traffic.Down)
	remained := ""
	if traffic.Total > 0 {
		total = common.FormatTraffic(traffic.Total)
		left := max(traffic.Total-(traffic.Up+traffic.Down), 0)
		remained = common.FormatTraffic(left)
	}

	return PageData{
		Host:         hostHeader,
		BasePath:     basePath,
		SId:          subId,
		Download:     download,
		Upload:       upload,
		Total:        total,
		Used:         used,
		Remained:     remained,
		Expire:       traffic.ExpiryTime / 1000,
		LastOnline:   lastOnline,
		Datepicker:   s.resolveDatepicker(),
		DownloadByte: traffic.Down,
		UploadByte:   traffic.Up,
		TotalByte:    traffic.Total,
		SubUrl:       subURL,
		SubJsonUrl:   subJsonURL,
		SubClashUrl:  subClashURL,
		Result:       subs,
	}
}

func getHostFromXFH(s string) (string, error) {
	if strings.Contains(s, ":") {
		realHost, _, err := net.SplitHostPort(s)
		if err != nil {
			return "", err
		}
		return realHost, nil
	}
	return s, nil
}
