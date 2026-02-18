package job

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/valyala/fasthttp"
)

// XrayTrafficJob collects and processes traffic statistics from Xray, updating the database and optionally informing external APIs.
type XrayTrafficJob struct {
	settingService  service.SettingService
	xrayService     service.XrayService
	inboundService  service.InboundService
	outboundService service.OutboundService
	l2tpService     service.L2tpService
	pptpService     service.PptpService
	openvpnService  service.OpenVpnService
	nftService      service.NftService
	radiusService   *service.RadiusService
}

// NewXrayTrafficJob creates a new traffic collection job instance.
func NewXrayTrafficJob(rs *service.RadiusService) *XrayTrafficJob {
	return &XrayTrafficJob{radiusService: rs}
}

// Run collects traffic statistics from Xray and updates the database, triggering restart if needed.
func (j *XrayTrafficJob) Run() {
	var traffics []*xray.Traffic
	var clientTraffics []*xray.ClientTraffic

	if j.xrayService.IsXrayRunning() {
		var err error
		traffics, clientTraffics, err = j.xrayService.GetXrayTraffic()
		if err != nil {
			traffics = nil
			clientTraffics = nil
		}
	}

	// Collect L2TP, PPTP, and OpenVPN per-client traffic from nftables counters (atomic read+reset)
	// Session maps (IP→email) come from the embedded RADIUS server
	// This runs regardless of Xray status — VPN traffic is independent
	l2tpSessions := j.radiusService.GetSessions("l2tp")
	pptpSessions := j.radiusService.GetSessions("pptp")
	ovpnSessions := j.radiusService.GetSessions("openvpn")
	if l2tpTraffics, pptpTraffics, ovpnTraffics := j.nftService.CollectAndResetTraffic(l2tpSessions, pptpSessions, ovpnSessions); len(l2tpTraffics) > 0 || len(pptpTraffics) > 0 || len(ovpnTraffics) > 0 {
		clientTraffics = append(clientTraffics, l2tpTraffics...)
		clientTraffics = append(clientTraffics, pptpTraffics...)
		clientTraffics = append(clientTraffics, ovpnTraffics...)
	}

	// Skip DB update if no traffic to process
	if len(traffics) == 0 && len(clientTraffics) == 0 {
		return
	}

	err, needRestart0, l2tpDisabledEmails, pptpDisabledEmails, ovpnDisabledEmails := j.inboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add inbound traffic failed:", err)
	}
	// Enforce limits on L2TP clients (kill sessions, regenerate chap-secrets)
	if len(l2tpDisabledEmails) > 0 {
		j.l2tpService.DisableClients(l2tpDisabledEmails)
	}
	// Enforce limits on PPTP clients
	if len(pptpDisabledEmails) > 0 {
		j.pptpService.DisableClients(pptpDisabledEmails)
	}
	// Enforce limits on OpenVPN clients
	if len(ovpnDisabledEmails) > 0 {
		j.openvpnService.DisableClients(ovpnDisabledEmails)
	}
	err, needRestart1 := j.outboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add outbound traffic failed:", err)
	}
	if ExternalTrafficInformEnable, err := j.settingService.GetExternalTrafficInformEnable(); ExternalTrafficInformEnable {
		j.informTrafficToExternalAPI(traffics, clientTraffics)
	} else if err != nil {
		logger.Warning("get ExternalTrafficInformEnable failed:", err)
	}
	if needRestart0 || needRestart1 {
		j.xrayService.SetToNeedRestart()
	}

	// Get online clients and last online map for real-time status updates
	onlineClients := j.inboundService.GetOnlineClients()
	lastOnlineMap, err := j.inboundService.GetClientsLastOnline()
	if err != nil {
		logger.Warning("get clients last online failed:", err)
		lastOnlineMap = make(map[string]int64)
	}

	// Fetch updated inbounds from database with accumulated traffic values
	// This ensures frontend receives the actual total traffic, not just delta values
	updatedInbounds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("get all inbounds for websocket failed:", err)
	}

	updatedOutbounds, err := j.outboundService.GetOutboundsTraffic()
	if err != nil {
		logger.Warning("get all outbounds for websocket failed:", err)
	}

	// Broadcast traffic update via WebSocket with accumulated values from database
	trafficUpdate := map[string]any{
		"traffics":       traffics,
		"clientTraffics": clientTraffics,
		"onlineClients":  onlineClients,
		"lastOnlineMap":  lastOnlineMap,
	}
	websocket.BroadcastTraffic(trafficUpdate)

	// Broadcast full inbounds update for real-time UI refresh
	if updatedInbounds != nil {
		websocket.BroadcastInbounds(updatedInbounds)
	}

	if updatedOutbounds != nil {
		websocket.BroadcastOutbounds(updatedOutbounds)
	}

}

func (j *XrayTrafficJob) informTrafficToExternalAPI(inboundTraffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic) {
	informURL, err := j.settingService.GetExternalTrafficInformURI()
	if err != nil {
		logger.Warning("get ExternalTrafficInformURI failed:", err)
		return
	}
	requestBody, err := json.Marshal(map[string]any{"clientTraffics": clientTraffics, "inboundTraffics": inboundTraffics})
	if err != nil {
		logger.Warning("parse client/inbound traffic failed:", err)
		return
	}
	request := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(request)
	request.Header.SetMethod("POST")
	request.Header.SetContentType("application/json; charset=UTF-8")
	request.SetBody([]byte(requestBody))
	request.SetRequestURI(informURL)
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(response)
	if err := fasthttp.Do(request, response); err != nil {
		logger.Warning("POST ExternalTrafficInformURI failed:", err)
	}
}
