package sub

import (
	"net/url"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func credInbound(proto model.Protocol, port int, settings string) *model.Inbound {
	return &model.Inbound{Protocol: proto, Port: port, Settings: settings}
}

// cardService builds a SubService with a fixed remark model. genRemark indexes
// remarkModel[0], so a zero-value SubService panics: the model is not optional.
func cardService() *SubService {
	return &SubService{address: "vpn.example.com", remarkModel: "-ieo"}
}

// parseCard fails the test unless the card is a URI a subscription importer can read,
// which is the whole reason it exists, and returns it decoded.
func parseCard(t *testing.T, card string) *url.URL {
	t.Helper()
	if card == "" {
		t.Fatal("no card emitted")
	}
	u, err := url.Parse(card)
	if err != nil {
		t.Fatalf("card is not a parseable URI (%v): %q", err, card)
	}
	if u.Scheme != "trojan" {
		t.Fatalf("want a trojan card, got scheme %q: %q", u.Scheme, card)
	}
	if u.Fragment == "" {
		t.Fatalf("card has no name, so no client would show anything: %q", card)
	}
	return u
}

// The protocols Xray has no outbound for get a connection card. These lock the parts a
// client actually consumes: the endpoint, the credential slot, and the name that carries
// the connection details.
func TestGenConnectionCard(t *testing.T) {
	s := cardService()

	ovpn := credInbound(model.OPENVPN, 1194, `{"clients":[{"email":"alice","password":"pw1"}]}`)
	u := parseCard(t, s.genConnectionCard(ovpn, "alice"))
	if u.Host != "vpn.example.com:1194" {
		t.Fatalf("endpoint: got %q", u.Host)
	}
	if pw, _ := u.User.Password(); pw != "" || u.User.Username() != "pw1" {
		t.Fatalf("credential slot: got %q", u.User.String())
	}
	if want := "alice-OpenVPN user=alice pass=pw1"; u.Fragment != want {
		t.Fatalf("name:\n got=%q\nwant=%q", u.Fragment, want)
	}

	// The inbound remark leads the name, exactly as it does for an Xray node.
	remarked := credInbound(model.PPTP, 1723, `{"clients":[{"email":"bob","password":"pw2"}]}`)
	remarked.Remark = "home"
	if got, want := parseCard(t, s.genConnectionCard(remarked, "bob")).Fragment,
		"home-bob-PPTP user=bob pass=pw2"; got != want {
		t.Fatalf("remarked name:\n got=%q\nwant=%q", got, want)
	}

	// L2TP with IPsec on -> PSK in the name.
	l2tp := credInbound(model.L2TP, 1701, `{"ipsecEnable":true,"ipsecPsk":"mypsk","clients":[{"email":"bob","password":"pw2"}]}`)
	if got := parseCard(t, s.genConnectionCard(l2tp, "bob")).Fragment; !strings.HasSuffix(got, " psk=mypsk") {
		t.Fatalf("l2tp psk missing from name: %q", got)
	}

	// IPsec off -> no PSK even if a stale value lingers in settings.
	l2tpNoIpsec := credInbound(model.L2TP, 1701, `{"ipsecEnable":false,"ipsecPsk":"stale","clients":[{"email":"c","password":"p"}]}`)
	if got := parseCard(t, s.genConnectionCard(l2tpNoIpsec, "c")).Fragment; strings.Contains(got, "psk") {
		t.Fatalf("l2tp without ipsec should not show a psk: %q", got)
	}

	// IKEv2: PSK only in psk mode, never in eap mode.
	ikePsk := credInbound(model.IKEV2, 500, `{"authMode":"psk","psk":"ikepsk","clients":[{"email":"d","password":"p"}]}`)
	if got := parseCard(t, s.genConnectionCard(ikePsk, "d")).Fragment; !strings.Contains(got, "psk=ikepsk") {
		t.Fatalf("ikev2 psk should show a psk: %q", got)
	}
	ikeEap := credInbound(model.IKEV2, 500, `{"authMode":"eap-mschapv2","psk":"unused","clients":[{"email":"e","password":"p"}]}`)
	if got := parseCard(t, s.genConnectionCard(ikeEap, "e")).Fragment; strings.Contains(got, "psk") {
		t.Fatalf("ikev2 eap should not show a psk: %q", got)
	}

	// A psk/eap-tls ikev2 account is email-only: no password to put in the credential
	// slot, and a URI with an empty userinfo is what a strict parser rejects.
	single := credInbound(model.IKEV2, 500, `{"authMode":"psk","psk":"k","clients":[{"email":"solo"}]}`)
	if got := parseCard(t, s.genConnectionCard(single, "solo")).User.Username(); got != "solo" {
		t.Fatalf("email-only account credential slot: got %q", got)
	}

	// mtproto's credential is its secret, not a password.
	mt := credInbound(model.MTPROTO, 8443, `{"clients":[{"email":"f","secret":"0123456789abcdef0123456789abcdef"}]}`)
	mtCard := parseCard(t, s.genConnectionCard(mt, "f"))
	if mtCard.User.Username() != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("mtproto credential slot: got %q", mtCard.User.Username())
	}
	if want := "f-MTProto secret=0123456789abcdef0123456789abcdef"; mtCard.Fragment != want {
		t.Fatalf("mtproto name:\n got=%q\nwant=%q", mtCard.Fragment, want)
	}

	// An unknown email yields no card (nothing to leak).
	if got := s.genConnectionCard(ovpn, "nobody"); got != "" {
		t.Fatalf("unknown email should yield empty: %q", got)
	}
}

// The SSH gateway compares the client id and nothing else (SshService.lookupAccount), so
// the card must show that, not the account email: an email here is a username the
// subscriber cannot log in with.
func TestConnectionCardUsesSshLoginName(t *testing.T) {
	s := cardService()
	in := credInbound(model.SSH, 2222,
		`{"clients":[{"id":"1q8r13d3","email":"acct-email","password":"pw"}]}`)
	got := parseCard(t, s.genConnectionCard(in, "acct-email")).Fragment
	if !strings.Contains(got, "user=1q8r13d3") {
		t.Fatalf("ssh card should show the client id as the username: %q", got)
	}
	if strings.Contains(got, "user=acct-email") {
		t.Fatalf("ssh card must not show the email as the username: %q", got)
	}
}

// VPN protocols (l2tp, pptp, openvpn, etc.) must show the client ID (the vpnUsername)
// in the card if one is set, rather than the tracking email.
func TestConnectionCardUsesVpnUsername(t *testing.T) {
	s := cardService()
	in := credInbound(model.L2TP, 1701,
		`{"ipsecEnable":true,"ipsecPsk":"psk1","clients":[{"id":"samael-l2","email":"samael@example.com","password":"pw"}]}`)
	got := parseCard(t, s.genConnectionCard(in, "samael@example.com")).Fragment
	if !strings.Contains(got, "user=samael-l2") {
		t.Fatalf("l2tp card should show the vpn username from id: %q", got)
	}
	if strings.Contains(got, "user=samael@example.com") {
		t.Fatalf("l2tp card must not show the email when id is set: %q", got)
	}
}

// An inbound with externalProxy should emit cards with the relay host and port instead of s.address.
func TestConnectionCardRespectsExternalProxy(t *testing.T) {
	s := cardService()
	in := credInbound(model.L2TP, 1701,
		`{"externalProxy":[{"dest":"relay.example.com","port":1701,"remark":"relay1"}],"clients":[{"id":"u1","email":"e1","password":"p"}]}`)
	card := s.genConnectionCard(in, "e1")
	u := parseCard(t, card)
	if u.Host != "relay.example.com:1701" {
		t.Fatalf("card host should be external proxy: got %q", u.Host)
	}
	if !strings.Contains(u.Fragment, "(relay1)") {
		t.Fatalf("card remark should contain external proxy remark: %q", u.Fragment)
	}
}

// Spaces in a name must be %20, never '+': a '+' in a fragment is a literal plus, so a
// client would display "user=x+pass=y". url.URL gets this right and QueryEscape does not,
// which is the trap this pins.
func TestConnectionCardEscapesNameForClients(t *testing.T) {
	s := cardService()
	in := credInbound(model.SSTP, 443, `{"clients":[{"email":"g","password":"p p"}]}`)
	card := s.genConnectionCard(in, "g")
	if strings.Contains(card, "+") {
		t.Fatalf("name must not use '+' for spaces: %q", card)
	}
	if !strings.Contains(card, "%20") {
		t.Fatalf("name spaces should be percent-encoded: %q", card)
	}
	if got := parseCard(t, card).Fragment; got != "g-SSTP user=g pass=p p" {
		t.Fatalf("round trip: got %q", got)
	}
}

// GRE gets NO entry of any kind. Its peer is a ROUTER, so there is no app to import a URI,
// and the inbound has no port for one to name: 47 is the IP protocol number, and the card
// this used to emit was a trojan:// link to a TCP port nothing listens on, which every
// client then offered as a connectable node. Its delivery is the config-file download.
func TestGreYieldsNoLink(t *testing.T) {
	s := cardService()
	gre := credInbound(model.GRE, 47,
		`{"clients":[{"email":"alice","enable":true,"peers":[{"peerIp":"198.51.100.4"}]}]}`)
	gre.Remark = "home"
	if got := s.getLink(gre, "alice"); got != "" {
		t.Fatalf("gre must produce no share link, got %q", got)
	}

	// The protocols beside it in that switch are unaffected: they have a real endpoint and
	// a real credential, and the card is the only thing that makes them visible in a client.
	for _, p := range []model.Protocol{model.OPENVPN, model.L2TP, model.PPTP,
		model.OPENCONNECT, model.SSTP, model.IKEV2} {
		in := credInbound(p, 1194, `{"clients":[{"email":"alice","password":"pw"}]}`)
		if s.getLink(in, "alice") == "" {
			t.Fatalf("%s lost its connection card", p)
		}
	}
}

// mtproto and ssh keep their own protocol-native link AND get a card, so Telegram (or
// Shadowrocket) still works while a subscription importer has something to keep.
func TestMtprotoAndSshCarryNativeLinkPlusCard(t *testing.T) {
	s := cardService()
	// modeClassic is the INBOUND's: telemt's listener modes are process-wide.
	mt := credInbound(model.MTPROTO, 8443,
		`{"modeClassic":true,"clients":[{"email":"h","secret":"0123456789abcdef0123456789abcdef"}]}`)
	lines := strings.Split(s.getLink(mt, "h"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want tg:// + card, got %d line(s): %q", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "tg://proxy?") {
		t.Fatalf("first line should be the Telegram link: %q", lines[0])
	}
	parseCard(t, lines[1])
}
