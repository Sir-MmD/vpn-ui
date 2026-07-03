package job

import (
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

// CheckVpnDokodemoJob keeps Xray's per-VPN dokodemo-door ports bound. On a rapid
// restart Xray can silently fail to bind one of them, which cuts that
// L2TP/PPTP/OpenVPN inbound's route to the internet with no error. This job
// detects the missing port and flags Xray for a restart so it rebinds.
type CheckVpnDokodemoJob struct {
	coreService  service.CoreService
	xrayService  service.XrayService
	missStreak   int // consecutive checks with an unbound port
	healAttempts int // restarts flagged since the ports were last all-bound
}

// NewCheckVpnDokodemoJob creates a new VPN dokodemo health-check job.
func NewCheckVpnDokodemoJob() *CheckVpnDokodemoJob { return new(CheckVpnDokodemoJob) }

// Run flags an Xray restart when a VPN dokodemo port has been unbound for two
// consecutive checks (debounced so a normal in-progress restart isn't mistaken
// for a failure), and gives up after a few attempts so a genuinely unbindable
// port doesn't cause an endless restart loop.
func (j *CheckVpnDokodemoJob) Run() {
	// When Xray isn't running, leave it alone: a crash is handled by
	// CheckXrayRunningJob, and a manual stop (Core Settings) must not be undone.
	if !j.xrayService.IsXrayRunning() {
		j.missStreak = 0
		return
	}

	missing := j.coreService.MissingDokodemoPorts()
	if len(missing) == 0 {
		j.missStreak = 0
		j.healAttempts = 0
		return
	}

	j.missStreak++
	if j.missStreak < 2 {
		return
	}
	j.missStreak = 0

	if j.healAttempts >= 3 {
		logger.Error("VPN dokodemo ports still unbound after 3 restart attempts, giving up until they recover:", missing)
		return
	}
	j.healAttempts++
	// Force the restart: a non-forced one no-ops when the on-disk config is
	// unchanged (RestartXray only rebuilds when the config differs), but the
	// running instance is what's missing the listener, so we must rebuild it.
	logger.Warning("VPN dokodemo ports unbound, restarting Xray to rebind:", missing)
	if err := j.xrayService.RestartXray(true); err != nil {
		logger.Error("dokodemo health check: restart xray failed:", err)
	}
}
