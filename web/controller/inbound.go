package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"

	"github.com/gin-gonic/gin"
)

// InboundController handles HTTP requests related to Xray inbounds management.
type InboundController struct {
	inboundService service.InboundService
	xrayService    service.XrayService
	l2tpService    service.L2tpService
	pptpService    service.PptpService
	openvpnService service.OpenVpnService
}

// NewInboundController creates a new InboundController and sets up its routes.
func NewInboundController(g *gin.RouterGroup) *InboundController {
	a := &InboundController{}
	a.initRouter(g)
	return a
}

// initRouter initializes the routes for inbound-related operations.
func (a *InboundController) initRouter(g *gin.RouterGroup) {

	g.GET("/list", a.getInbounds)
	g.GET("/get/:id", a.getInbound)
	g.GET("/getClientTraffics/:email", a.getClientTraffics)
	g.GET("/getClientTrafficsById/:id", a.getClientTrafficsById)

	g.POST("/add", a.addInbound)
	g.POST("/del/:id", a.delInbound)
	g.POST("/update/:id", a.updateInbound)
	g.POST("/clientIps/:email", a.getClientIps)
	g.POST("/clearClientIps/:email", a.clearClientIps)
	g.POST("/addClient", a.addInboundClient)
	g.POST("/:id/copyClients", a.copyInboundClients)
	g.POST("/:id/delClient/:clientId", a.delInboundClient)
	g.POST("/updateClient/:clientId", a.updateInboundClient)
	g.POST("/bulkUpdateClients", a.bulkUpdateClients)
	g.POST("/:id/resetClientTraffic/:email", a.resetClientTraffic)
	g.POST("/resetAllTraffics", a.resetAllTraffics)
	g.POST("/resetAllClientTraffics/:id", a.resetAllClientTraffics)
	g.POST("/delDepletedClients/:id", a.delDepletedClients)
	g.POST("/import", a.importInbound)
	g.POST("/onlines", a.onlines)
	g.POST("/lastOnline", a.lastOnline)
	g.POST("/updateClientTraffic/:email", a.updateClientTraffic)
	g.POST("/:id/delClientByEmail/:email", a.delInboundClientByEmail)
	g.GET("/:id/ovpn/:proto", a.downloadOvpn)
	g.POST("/:id/generate-openvpn-certs", a.generateOpenVpnCerts)
	// id-less variant so certs can be generated for a not-yet-saved inbound
	g.POST("/generate-openvpn-certs", a.generateOpenVpnCerts)
}

// onL2tpChanged regenerates L2TP configs and restarts services when an L2TP inbound is modified.
func (a *InboundController) onL2tpChanged() {
	service.AutoExpandVpnRanges("l2tp")
	if err := a.l2tpService.GenerateAllConfigs(); err != nil {
		logger.Warning("L2TP: config generation failed:", err)
	}
	if err := a.l2tpService.SetupAllTproxy(); err != nil {
		logger.Warning("L2TP: TPROXY setup failed:", err)
	}
	if err := a.l2tpService.RestartServices(); err != nil {
		logger.Warning("L2TP: service restart failed:", err)
	}
	a.l2tpService.KillDisabledSessions()
	a.xrayService.SetToNeedRestart()
}

// onPptpChanged regenerates PPTP configs and restarts services when a PPTP inbound is modified.
func (a *InboundController) onPptpChanged() {
	service.AutoExpandVpnRanges("pptp")
	if err := a.pptpService.GenerateAllConfigs(); err != nil {
		logger.Warning("PPTP: config generation failed:", err)
	}
	if err := a.pptpService.SetupAllTproxy(); err != nil {
		logger.Warning("PPTP: TPROXY setup failed:", err)
	}
	if err := a.pptpService.RestartServices(); err != nil {
		logger.Warning("PPTP: service restart failed:", err)
	}
	a.pptpService.KillDisabledSessions()
	a.xrayService.SetToNeedRestart()
}

// onOpenVpnChanged regenerates OpenVPN configs and restarts services when an OpenVPN inbound is modified.
func (a *InboundController) onOpenVpnChanged() {
	service.AutoExpandVpnRanges("openvpn")
	if err := a.openvpnService.GenerateAllConfigs(); err != nil {
		logger.Warning("OpenVPN: config generation failed:", err)
	}
	if err := a.openvpnService.SetupRouting(); err != nil {
		logger.Warning("OpenVPN: routing setup failed:", err)
	}
	if err := a.openvpnService.RestartServices(); err != nil {
		logger.Warning("OpenVPN: service restart failed:", err)
	}
	a.openvpnService.KillDisabledSessions()
	// OpenVPN now routes through Xray via dokodemo-door, so its config must be
	// regenerated (and Xray restarted) when an OpenVPN inbound changes.
	a.xrayService.SetToNeedRestart()
}

type CopyInboundClientsRequest struct {
	SourceInboundID int      `form:"sourceInboundId" json:"sourceInboundId"`
	ClientEmails    []string `form:"clientEmails" json:"clientEmails"`
	Flow            string   `form:"flow" json:"flow"`
}

// getInbounds retrieves the list of inbounds for the logged-in user.
func (a *InboundController) getInbounds(c *gin.Context) {
	user := session.GetLoginUser(c)
	inbounds, err := a.inboundService.GetInbounds(user.Id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.obtain"), err)
		return
	}
	jsonObj(c, inbounds, nil)
}

// getInbound retrieves a specific inbound by its ID.
func (a *InboundController) getInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.obtain"), err)
		return
	}
	jsonObj(c, inbound, nil)
}

// getClientTraffics retrieves client traffic information by email.
func (a *InboundController) getClientTraffics(c *gin.Context) {
	email := c.Param("email")
	clientTraffics, err := a.inboundService.GetClientTrafficByEmail(email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.trafficGetError"), err)
		return
	}
	jsonObj(c, clientTraffics, nil)
}

// getClientTrafficsById retrieves client traffic information by inbound ID.
func (a *InboundController) getClientTrafficsById(c *gin.Context) {
	id := c.Param("id")
	clientTraffics, err := a.inboundService.GetClientTrafficByID(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.trafficGetError"), err)
		return
	}
	jsonObj(c, clientTraffics, nil)
}

// addInbound creates a new inbound configuration.
func (a *InboundController) addInbound(c *gin.Context) {
	inbound := &model.Inbound{}
	err := c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundCreateSuccess"), err)
		return
	}

	// VPN protocols (L2TP/PPTP/OpenVPN) require the host backend to be provisioned
	// first (kernel modules, daemons, IPsec). Block creation with a clear message
	// until the operator runs setup from Core Settings. The UI guards this too;
	// this is defense-in-depth against a direct API call.
	if inbound.Protocol == model.L2TP || inbound.Protocol == model.PPTP || inbound.Protocol == model.OPENVPN {
		var coreService service.CoreService
		if !coreService.IsProvisioned() {
			pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.inbounds.toasts.setupRequired"))
			return
		}
	}

	user := session.GetLoginUser(c)
	inbound.UserId = user.Id
	if inbound.Listen == "" || inbound.Listen == "0.0.0.0" || inbound.Listen == "::" || inbound.Listen == "::0" {
		inbound.Tag = fmt.Sprintf("inbound-%v", inbound.Port)
	} else {
		inbound.Tag = fmt.Sprintf("inbound-%v:%v", inbound.Listen, inbound.Port)
	}

	// Assign/validate VPN client IP ranges (no-op for non-VPN protocols). A
	// user-supplied range overlapping another inbound is rejected here.
	if err := service.NormalizeVpnRanges(inbound, 0); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	inbound, needRestart, err := a.inboundService.AddInbound(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundCreateSuccess"), inbound, nil)
	if inbound.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if inbound.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if inbound.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket
	inbounds, _ := a.inboundService.GetInbounds(user.Id)
	websocket.BroadcastInbounds(inbounds)
}

// delInbound deletes an inbound configuration by its ID.
func (a *InboundController) delInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundDeleteSuccess"), err)
		return
	}
	// Check if this is an L2TP/PPTP/OpenVPN inbound before deletion
	oldInbound, _ := a.inboundService.GetInbound(id)
	isL2tp := oldInbound != nil && oldInbound.Protocol == model.L2TP
	isPptp := oldInbound != nil && oldInbound.Protocol == model.PPTP
	isOpenVpn := oldInbound != nil && oldInbound.Protocol == model.OPENVPN
	needRestart, err := a.inboundService.DelInbound(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundDeleteSuccess"), id, nil)
	if isL2tp {
		a.onL2tpChanged()
	} else if isPptp {
		a.onPptpChanged()
	} else if isOpenVpn {
		a.onOpenVpnChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket
	user := session.GetLoginUser(c)
	inbounds, _ := a.inboundService.GetInbounds(user.Id)
	websocket.BroadcastInbounds(inbounds)
}

// updateInbound updates an existing inbound configuration.
func (a *InboundController) updateInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	inbound := &model.Inbound{
		Id: id,
	}
	err = c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	// Assign/validate VPN client IP ranges (no-op for non-VPN protocols),
	// excluding this inbound so its own ranges aren't seen as overlaps.
	if err := service.NormalizeVpnRanges(inbound, id); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	inbound, needRestart, err := a.inboundService.UpdateInbound(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), inbound, nil)
	if inbound.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if inbound.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if inbound.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket
	user := session.GetLoginUser(c)
	inbounds, _ := a.inboundService.GetInbounds(user.Id)
	websocket.BroadcastInbounds(inbounds)
}

// getClientIps retrieves the IP addresses associated with a client by email.
func (a *InboundController) getClientIps(c *gin.Context) {
	email := c.Param("email")

	ips, err := a.inboundService.GetInboundClientIps(email)
	if err != nil || ips == "" {
		jsonObj(c, "No IP Record", nil)
		return
	}

	// Prefer returning a normalized string list for consistent UI rendering
	type ipWithTimestamp struct {
		IP        string `json:"ip"`
		Timestamp int64  `json:"timestamp"`
	}

	var ipsWithTime []ipWithTimestamp
	if err := json.Unmarshal([]byte(ips), &ipsWithTime); err == nil && len(ipsWithTime) > 0 {
		formatted := make([]string, 0, len(ipsWithTime))
		for _, item := range ipsWithTime {
			if item.IP == "" {
				continue
			}
			if item.Timestamp > 0 {
				ts := time.Unix(item.Timestamp, 0).Local().Format("2006-01-02 15:04:05")
				formatted = append(formatted, fmt.Sprintf("%s (%s)", item.IP, ts))
				continue
			}
			formatted = append(formatted, item.IP)
		}
		jsonObj(c, formatted, nil)
		return
	}

	var oldIps []string
	if err := json.Unmarshal([]byte(ips), &oldIps); err == nil && len(oldIps) > 0 {
		jsonObj(c, oldIps, nil)
		return
	}

	// If parsing fails, return as string
	jsonObj(c, ips, nil)
}

// clearClientIps clears the IP addresses for a client by email.
func (a *InboundController) clearClientIps(c *gin.Context) {
	email := c.Param("email")

	err := a.inboundService.ClearClientIps(email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.updateSuccess"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.logCleanSuccess"), nil)
}

// addInboundClient adds a new client to an existing inbound.
func (a *InboundController) addInboundClient(c *gin.Context) {
	data := &model.Inbound{}
	err := c.ShouldBind(data)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	needRestart, err := a.inboundService.AddInboundClient(data)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientAddSuccess"), nil)

	// The request body may not include protocol, so look it up from the DB.
	if data.Protocol == "" {
		if dbInbound, err := a.inboundService.GetInbound(data.Id); err == nil {
			data.Protocol = dbInbound.Protocol
		}
	}

	if data.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if data.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if data.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// copyInboundClients copies clients from source inbound to target inbound.
func (a *InboundController) copyInboundClients(c *gin.Context) {
	targetID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	req := &CopyInboundClientsRequest{}
	err = c.ShouldBind(req)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	if req.SourceInboundID <= 0 {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), fmt.Errorf("invalid source inbound id"))
		return
	}

	result, needRestart, err := a.inboundService.CopyInboundClients(targetID, req.SourceInboundID, req.ClientEmails, req.Flow)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, result, nil)
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// delInboundClient deletes a client from an inbound by inbound ID and client ID.
func (a *InboundController) delInboundClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	clientId := c.Param("clientId")

	oldInbound, _ := a.inboundService.GetInbound(id)
	needRestart, err := a.inboundService.DelInboundClient(id, clientId)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientDeleteSuccess"), nil)
	if oldInbound != nil && oldInbound.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// updateInboundClient updates a client's configuration in an inbound.
func (a *InboundController) updateInboundClient(c *gin.Context) {
	clientId := c.Param("clientId")

	inbound := &model.Inbound{}
	err := c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	needRestart, err := a.inboundService.UpdateInboundClient(inbound, clientId)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientUpdateSuccess"), nil)

	// The request body may not include protocol, so look it up from the DB.
	if inbound.Protocol == "" {
		if dbInbound, err := a.inboundService.GetInbound(inbound.Id); err == nil {
			inbound.Protocol = dbInbound.Protocol
		}
	}

	if inbound.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if inbound.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if inbound.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// bulkUpdateClients applies one operation (add/subtract days or traffic, enable,
// disable) to many selected clients at once, then regenerates the touched subsystems
// once each. The payload arrives as a JSON string in the form field "data" (the panel
// axios interceptor form-encodes bodies).
func (a *InboundController) bulkUpdateClients(c *gin.Context) {
	var body struct {
		Data string `form:"data" json:"data"`
	}
	if err := c.ShouldBind(&body); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	var req service.BulkClientUpdateRequest
	if err := json.Unmarshal([]byte(body.Data), &req); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	result, touched, err := a.inboundService.BulkUpdateClients(req)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, result, nil)

	xrayRestart := false
	for proto := range touched {
		switch proto {
		case string(model.L2TP):
			a.onL2tpChanged()
		case string(model.PPTP):
			a.onPptpChanged()
		case string(model.OPENVPN):
			a.onOpenVpnChanged()
		default:
			xrayRestart = true
		}
	}
	if xrayRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// resetClientTraffic resets the traffic counter for a specific client in an inbound.
func (a *InboundController) resetClientTraffic(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	email := c.Param("email")

	needRestart, err := a.inboundService.ResetClientTraffic(id, email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.resetInboundClientTrafficSuccess"), nil)
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	a.onL2tpChanged()
	a.onPptpChanged()
	a.onOpenVpnChanged()
}

// resetAllTraffics resets all traffic counters across all inbounds.
func (a *InboundController) resetAllTraffics(c *gin.Context) {
	err := a.inboundService.ResetAllTraffics()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	} else {
		a.xrayService.SetToNeedRestart()
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.resetAllTrafficSuccess"), nil)
	a.onL2tpChanged()
	a.onPptpChanged()
	a.onOpenVpnChanged()
}

// resetAllClientTraffics resets traffic counters for all clients in a specific inbound.
func (a *InboundController) resetAllClientTraffics(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	err = a.inboundService.ResetAllClientTraffics(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	} else {
		a.xrayService.SetToNeedRestart()
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.resetAllClientTrafficSuccess"), nil)
	a.onL2tpChanged()
	a.onPptpChanged()
	a.onOpenVpnChanged()
}

// importInbound imports an inbound configuration from provided data.
func (a *InboundController) importInbound(c *gin.Context) {
	inbound := &model.Inbound{}
	err := json.Unmarshal([]byte(c.PostForm("data")), inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	user := session.GetLoginUser(c)
	inbound.Id = 0
	inbound.UserId = user.Id
	if inbound.Listen == "" || inbound.Listen == "0.0.0.0" || inbound.Listen == "::" || inbound.Listen == "::0" {
		inbound.Tag = fmt.Sprintf("inbound-%v", inbound.Port)
	} else {
		inbound.Tag = fmt.Sprintf("inbound-%v:%v", inbound.Listen, inbound.Port)
	}

	for index := range inbound.ClientStats {
		inbound.ClientStats[index].Id = 0
		inbound.ClientStats[index].Enable = true
	}

	needRestart := false
	inbound, needRestart, err = a.inboundService.AddInbound(inbound)
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundCreateSuccess"), inbound, err)
	if err == nil && needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// delDepletedClients deletes clients in an inbound who have exhausted their traffic limits.
func (a *InboundController) delDepletedClients(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	err = a.inboundService.DelDepletedClients(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.delDepletedClientsSuccess"), nil)
}

// onlines retrieves the list of currently online clients.
func (a *InboundController) onlines(c *gin.Context) {
	jsonObj(c, a.inboundService.GetOnlineClients(), nil)
}

// lastOnline retrieves the last online timestamps for clients.
func (a *InboundController) lastOnline(c *gin.Context) {
	data, err := a.inboundService.GetClientsLastOnline()
	jsonObj(c, data, err)
}

// updateClientTraffic updates the traffic statistics for a client by email.
func (a *InboundController) updateClientTraffic(c *gin.Context) {
	email := c.Param("email")

	// Define the request structure for traffic update
	type TrafficUpdateRequest struct {
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	}

	var request TrafficUpdateRequest
	err := c.ShouldBindJSON(&request)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	err = a.inboundService.UpdateClientTrafficByEmail(email, request.Upload, request.Download)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientUpdateSuccess"), nil)
}

// downloadOvpn generates and returns an .ovpn client config file.
func (a *InboundController) downloadOvpn(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	proto := c.Param("proto") // "udp" or "tcp"
	if proto != "udp" && proto != "tcp" {
		jsonMsg(c, "Invalid protocol, must be udp or tcp", nil)
		return
	}

	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}

	content, err := a.openvpnService.GenerateClientConfig(inbound, proto)
	if err != nil {
		jsonMsg(c, "Failed to generate client config", err)
		return
	}

	filename := fmt.Sprintf("client-%s.ovpn", proto)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(200, "application/x-openvpn-profile", []byte(content))
}

// generateOpenVpnCerts generates a self-signed CA, server cert, and tls-crypt
// key for OpenVPN. Certificate generation does not need a saved inbound — the
// material is returned to the caller. When called with a valid inbound id (the
// edit case) the certs are also persisted to that inbound and applied; for a
// new (unsaved) inbound the frontend stores them in the form and the normal
// "Add inbound" save persists + applies them.
func (a *InboundController) generateOpenVpnCerts(c *gin.Context) {
	caCert, caKey, serverCert, serverKey, tlsCrypt, err := a.openvpnService.GenerateSelfSignedCA()
	if err != nil {
		jsonMsg(c, "Failed to generate certificates", err)
		return
	}

	// If editing an existing inbound, persist the certs to it and apply them.
	if id, err := strconv.Atoi(c.Param("id")); err == nil && id > 0 {
		inbound, err := a.inboundService.GetInbound(id)
		if err != nil {
			jsonMsg(c, "Inbound not found", err)
			return
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			jsonMsg(c, "Failed to parse settings", err)
			return
		}
		settings["caCert"] = caCert
		settings["caKey"] = caKey
		settings["serverCert"] = serverCert
		settings["serverKey"] = serverKey
		settings["tlsCrypt"] = tlsCrypt

		settingsJSON, _ := json.Marshal(settings)
		inbound.Settings = string(settingsJSON)
		if _, _, err := a.inboundService.UpdateInbound(inbound); err != nil {
			jsonMsg(c, "Failed to save certificates", err)
			return
		}
		a.onOpenVpnChanged()
	}

	jsonObj(c, map[string]string{
		"caCert":     caCert,
		"caKey":      caKey,
		"serverCert": serverCert,
		"serverKey":  serverKey,
		"tlsCrypt":   tlsCrypt,
	}, nil)
}

// delInboundClientByEmail deletes a client from an inbound by email address.
func (a *InboundController) delInboundClientByEmail(c *gin.Context) {
	inboundId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}

	email := c.Param("email")
	needRestart, err := a.inboundService.DelInboundClientByEmail(inboundId, email)
	if err != nil {
		jsonMsg(c, "Failed to delete client by email", err)
		return
	}

	jsonMsg(c, "Client deleted successfully", nil)
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}
