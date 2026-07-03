package controller

import (
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// CoreController exposes status and control for the backend "cores"
// (Xray, L2TP/IPsec, PPTP, OpenVPN, RADIUS) shown in the Core Settings panel.
type CoreController struct {
	coreService service.CoreService
}

// NewCoreController creates a new CoreController and initializes its routes.
func NewCoreController(g *gin.RouterGroup) *CoreController {
	a := &CoreController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for core status and control under /panel/core.
func (a *CoreController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/core")
	g.GET("/status", a.status)
	g.POST("/provision", a.provision)
	g.POST("/restart/:core", a.restart)
	g.POST("/restart-all", a.restartAll)
	g.POST("/stop/:core", a.stop)
	g.GET("/logs/:core", a.logs)
}

// status returns the status of all cores plus the host/kernel system status.
func (a *CoreController) status(c *gin.Context) {
	jsonObj(c, gin.H{
		"cores":  a.coreService.GetCoresStatus(),
		"system": a.coreService.GetSystemStatus(),
	}, nil)
}

// provision runs the host/kernel provisioning (kernel modules + sysctl) and
// returns a per-step report.
func (a *CoreController) provision(c *gin.Context) {
	jsonObj(c, a.coreService.Provision(), nil)
}

// restart restarts the daemon(s) for the given core.
func (a *CoreController) restart(c *gin.Context) {
	err := a.coreService.RestartCore(c.Param("core"))
	jsonMsg(c, I18nWeb(c, "pages.core.toasts.restarted"), err)
}

// restartAll restarts every core.
func (a *CoreController) restartAll(c *gin.Context) {
	err := a.coreService.RestartAll()
	jsonMsg(c, I18nWeb(c, "pages.core.toasts.restarted"), err)
}

// stop stops the given core, where supported (xray, l2tp, pptp, openvpn, radius).
func (a *CoreController) stop(c *gin.Context) {
	err := a.coreService.StopCore(c.Param("core"))
	jsonMsg(c, I18nWeb(c, "pages.core.toasts.stopped"), err)
}

// logs returns the recent captured output for a core's process(es).
func (a *CoreController) logs(c *gin.Context) {
	jsonObj(c, a.coreService.CoreLogs(c.Param("core")), nil)
}
