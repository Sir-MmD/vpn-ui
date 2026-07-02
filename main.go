// Package main is the entry point for the 3x-ui web panel application.
// It initializes the database, web server, and handles command-line operations for managing the panel.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	_ "unsafe"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/sub"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/web"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/joho/godotenv"
	"github.com/op/go-logging"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// runWebServer initializes and starts the web server for the 3x-ui panel.
func runWebServer() {
	log.Printf("Starting %v %v", config.GetName(), config.GetVersion())

	switch config.GetLogLevel() {
	case config.Debug:
		logger.InitLogger(logging.DEBUG)
	case config.Info:
		logger.InitLogger(logging.INFO)
	case config.Notice:
		logger.InitLogger(logging.NOTICE)
	case config.Warning:
		logger.InitLogger(logging.WARNING)
	case config.Error:
		logger.InitLogger(logging.ERROR)
	default:
		log.Fatalf("Unknown log level: %v", config.GetLogLevel())
	}

	godotenv.Load()

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	var server *web.Server
	server = web.NewServer()
	global.SetWebServer(server)
	err = server.Start()
	if err != nil {
		log.Fatalf("Error starting web server: %v", err)
		return
	}

	var subServer *sub.Server
	subServer = sub.NewServer()
	global.SetSubServer(subServer)
	err = subServer.Start()
	if err != nil {
		log.Fatalf("Error starting sub server: %v", err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	// Trap shutdown signals
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, sys.SIGUSR1)
	for {
		sig := <-sigCh

		switch sig {
		case syscall.SIGHUP:
			logger.Info("Received SIGHUP signal. Restarting servers...")

			// --- FIX FOR TELEGRAM BOT CONFLICT (409): Stop bot before restart ---
			service.StopBot()
			// --

			err := server.Stop()
			if err != nil {
				logger.Debug("Error stopping web server:", err)
			}
			err = subServer.Stop()
			if err != nil {
				logger.Debug("Error stopping sub server:", err)
			}

			server = web.NewServer()
			global.SetWebServer(server)
			err = server.Start()
			if err != nil {
				log.Fatalf("Error restarting web server: %v", err)
				return
			}
			log.Println("Web server restarted successfully.")

			subServer = sub.NewServer()
			global.SetSubServer(subServer)
			err = subServer.Start()
			if err != nil {
				log.Fatalf("Error restarting sub server: %v", err)
				return
			}
			log.Println("Sub server restarted successfully.")
		case sys.SIGUSR1:
			logger.Info("Received USR1 signal, restarting xray-core...")
			err := server.RestartXray()
			if err != nil {
				logger.Error("Failed to restart xray-core:", err)
			}

		default:
			// --- FIX FOR TELEGRAM BOT CONFLICT (409) on full shutdown ---
			service.StopBot()
			// ------------------------------------------------------------

			server.Stop()
			subServer.Stop()
			log.Println("Shutting down servers.")
			return
		}
	}
}

// resetSetting resets all panel settings to their default values.
func resetSetting() error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Failed to initialize database:", err)
		return err
	}

	settingService := service.SettingService{}
	err = settingService.ResetSettings()
	if err != nil {
		fmt.Println("Failed to reset settings:", err)
		return err
	} else {
		fmt.Println("Settings successfully reset.")
	}
	return nil
}

// showSetting displays the current panel settings if show is true.
func showSetting(show bool) {
	if show {
		settingService := service.SettingService{}
		port, err := settingService.GetPort()
		if err != nil {
			fmt.Println("get current port failed, error info:", err)
		}

		webBasePath, err := settingService.GetBasePath()
		if err != nil {
			fmt.Println("get webBasePath failed, error info:", err)
		}

		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		userService := service.UserService{}
		userModel, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("get current user info failed, error info:", err)
		}

		if userModel.Username == "" || userModel.Password == "" {
			fmt.Println("current username or password is empty")
		}

		fmt.Println("current panel settings as follows:")
		if certFile == "" || keyFile == "" {
			fmt.Println("Warning: Panel is not secure with SSL")
		} else {
			fmt.Println("Panel is secure with SSL")
		}

		hasDefaultCredential := func() bool {
			return userModel.Username == "admin" && crypto.CheckPasswordHash(userModel.Password, "admin")
		}()

		fmt.Println("hasDefaultCredential:", hasDefaultCredential)
		fmt.Println("port:", port)
		fmt.Println("webBasePath:", webBasePath)
	}
}

// updateTgbotEnableSts enables or disables the Telegram bot notifications based on the status parameter.
func updateTgbotEnableSts(status bool) {
	settingService := service.SettingService{}
	currentTgSts, err := settingService.GetTgbotEnabled()
	if err != nil {
		fmt.Println(err)
		return
	}
	logger.Infof("current enabletgbot status[%v],need update to status[%v]", currentTgSts, status)
	if currentTgSts != status {
		err := settingService.SetTgbotEnabled(status)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("SetTgbotEnabled[%v] success", status)
		}
	}
}

// updateTgbotSetting updates Telegram bot settings including token, chat ID, and runtime schedule.
func updateTgbotSetting(tgBotToken string, tgBotChatid string, tgBotRuntime string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Error initializing database:", err)
		return
	}

	settingService := service.SettingService{}

	if tgBotToken != "" {
		err := settingService.SetTgBotToken(tgBotToken)
		if err != nil {
			fmt.Printf("Error setting Telegram bot token: %v\n", err)
			return
		}
		logger.Info("Successfully updated Telegram bot token.")
	}

	if tgBotRuntime != "" {
		err := settingService.SetTgbotRuntime(tgBotRuntime)
		if err != nil {
			fmt.Printf("Error setting Telegram bot runtime: %v\n", err)
			return
		}
		logger.Infof("Successfully updated Telegram bot runtime to [%s].", tgBotRuntime)
	}

	if tgBotChatid != "" {
		err := settingService.SetTgBotChatId(tgBotChatid)
		if err != nil {
			fmt.Printf("Error setting Telegram bot chat ID: %v\n", err)
			return
		}
		logger.Info("Successfully updated Telegram bot chat ID.")
	}
}

// updateSetting updates various panel settings including port, credentials, base path, listen IP, and two-factor authentication.
func updateSetting(port int, username string, password string, webBasePath string, listenIP string, resetTwoFactor bool) error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Database initialization failed:", err)
		return err
	}

	settingService := service.SettingService{}
	userService := service.UserService{}

	if port > 0 {
		err := settingService.SetPort(port)
		if err != nil {
			fmt.Println("Failed to set port:", err)
		} else {
			fmt.Printf("Port set successfully: %v\n", port)
		}
	}

	if username != "" || password != "" {
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			fmt.Println("Failed to update username and password:", err)
		} else {
			fmt.Println("Username and password updated successfully")
		}
	}

	if webBasePath != "" {
		err := settingService.SetBasePath(webBasePath)
		if err != nil {
			fmt.Println("Failed to set base URI path:", err)
		} else {
			fmt.Println("Base URI path set successfully")
		}
	}

	if resetTwoFactor {
		err := settingService.SetTwoFactorEnable(false)

		if err != nil {
			fmt.Println("Failed to reset two-factor authentication:", err)
		} else {
			settingService.SetTwoFactorToken("")
			fmt.Println("Two-factor authentication reset successfully")
		}
	}

	if listenIP != "" {
		err := settingService.SetListen(listenIP)
		if err != nil {
			fmt.Println("Failed to set listen IP:", err)
		} else {
			fmt.Printf("listen %v set successfully", listenIP)
		}
	}

	return nil
}

// updateCert updates the SSL certificate files for the panel.
func updateCert(publicKey string, privateKey string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	if (privateKey != "" && publicKey != "") || (privateKey == "" && publicKey == "") {
		settingService := service.SettingService{}
		err = settingService.SetCertFile(publicKey)
		if err != nil {
			fmt.Println("set certificate public key failed:", err)
		} else {
			fmt.Println("set certificate public key success")
		}

		err = settingService.SetKeyFile(privateKey)
		if err != nil {
			fmt.Println("set certificate private key failed:", err)
		} else {
			fmt.Println("set certificate private key success")
		}

		err = settingService.SetSubCertFile(publicKey)
		if err != nil {
			fmt.Println("set certificate for subscription public key failed:", err)
		} else {
			fmt.Println("set certificate for subscription public key success")
		}

		err = settingService.SetSubKeyFile(privateKey)
		if err != nil {
			fmt.Println("set certificate for subscription private key failed:", err)
		} else {
			fmt.Println("set certificate for subscription private key success")
		}
	} else {
		fmt.Println("both public and private key should be entered.")
	}
}

// GetCertificate displays the current SSL certificate settings if getCert is true.
func GetCertificate(getCert bool) {
	if getCert {
		settingService := service.SettingService{}
		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		fmt.Println("cert:", certFile)
		fmt.Println("key:", keyFile)
	}
}

// GetListenIP displays the current panel listen IP address if getListen is true.
func GetListenIP(getListen bool) {
	if getListen {

		settingService := service.SettingService{}
		ListenIP, err := settingService.GetListen()
		if err != nil {
			log.Printf("Failed to retrieve listen IP: %v", err)
			return
		}

		fmt.Println("listenIP:", ListenIP)
	}
}

// migrateDb performs database migration operations for the 3x-ui panel.
func migrateDb() {
	inboundService := service.InboundService{}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Start migrating database...")
	inboundService.MigrateDB()
	fmt.Println("Migration done!")
}

// readRadiusSecret reads the RADIUS shared secret from /etc/ppp/radius/servers.
func readRadiusSecret() string {
	data, err := os.ReadFile("/etc/ppp/radius/servers")
	if err != nil {
		return ""
	}
	// Format: "127.0.0.1\t{secret}\n"
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "127.0.0.1" {
			return fields[1]
		}
	}
	return ""
}

// openvpnAuth handles OpenVPN auth-user-pass-verify via RADIUS PAP.
// Usage: x-ui openvpn-auth {inbound_id} {credentials_file}
// The credentials file has username on line 1, password on line 2.
func openvpnAuth() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: x-ui openvpn-auth <inbound_id> <cred_file>")
		os.Exit(1)
	}

	inboundId, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid inbound_id:", os.Args[2])
		os.Exit(1)
	}

	credFile := os.Args[3]
	data, err := os.ReadFile(credFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read credentials file:", err)
		os.Exit(1)
	}

	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) < 2 {
		fmt.Fprintln(os.Stderr, "credentials file must have username and password on separate lines")
		os.Exit(1)
	}
	username := strings.TrimSpace(lines[0])
	password := strings.TrimSpace(lines[1])

	secret := readRadiusSecret()
	if secret == "" {
		fmt.Fprintln(os.Stderr, "RADIUS secret not found")
		os.Exit(1)
	}

	// Send PAP Access-Request
	packet := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))

	resp, err := radius.Exchange(context.Background(), packet, "127.0.0.1:1812")
	if err != nil {
		fmt.Fprintln(os.Stderr, "RADIUS exchange failed:", err)
		os.Exit(1)
	}

	if resp.Code == radius.CodeAccessAccept {
		os.Exit(0) // Accept
	}
	os.Exit(1) // Reject
}

// openvpnConnect handles OpenVPN client-connect via RADIUS Acct-Start.
// Usage: x-ui openvpn-connect {inbound_id}
// Reads common_name and ifconfig_pool_remote_ip from environment.
func openvpnConnect() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: x-ui openvpn-connect <inbound_id>")
		os.Exit(1)
	}

	inboundId, _ := strconv.Atoi(os.Args[2])
	username := os.Getenv("common_name")
	ip := os.Getenv("ifconfig_pool_remote_ip")

	if username == "" || ip == "" {
		os.Exit(0) // Nothing to do
	}

	secret := readRadiusSecret()
	if secret == "" {
		os.Exit(0)
	}

	sessionID := fmt.Sprintf("openvpn-%d-%s-%s", inboundId, username, ip)

	packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Start)
	rfc2866.AcctSessionID_SetString(packet, sessionID)
	rfc2865.UserName_SetString(packet, username)
	rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))
	rfc2865.FramedIPAddress_Set(packet, net.ParseIP(ip))

	resp, err := radius.Exchange(context.Background(), packet, "127.0.0.1:1813")
	if err != nil {
		fmt.Fprintf(os.Stderr, "RADIUS acct-start failed: %v\n", err)
		os.Exit(0)
	}
	if resp.Code != radius.CodeAccountingResponse {
		fmt.Fprintf(os.Stderr, "RADIUS acct-start unexpected code: %v\n", resp.Code)
	}
	os.Exit(0)
}

// openvpnDisconnect handles OpenVPN client-disconnect via RADIUS Acct-Stop.
// Usage: x-ui openvpn-disconnect {inbound_id}
// Reads common_name and ifconfig_pool_remote_ip from environment.
func openvpnDisconnect() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: x-ui openvpn-disconnect <inbound_id>")
		os.Exit(1)
	}

	inboundId, _ := strconv.Atoi(os.Args[2])
	username := os.Getenv("common_name")
	ip := os.Getenv("ifconfig_pool_remote_ip")

	if username == "" || ip == "" {
		os.Exit(0)
	}

	secret := readRadiusSecret()
	if secret == "" {
		os.Exit(0)
	}

	sessionID := fmt.Sprintf("openvpn-%d-%s-%s", inboundId, username, ip)

	// Read session duration from env (OpenVPN provides time_duration in seconds)
	var sessionTime uint32
	if dur := os.Getenv("time_duration"); dur != "" {
		if d, err := strconv.ParseUint(dur, 10, 32); err == nil {
			sessionTime = uint32(d)
		}
	}

	packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(packet, sessionID)
	rfc2865.UserName_SetString(packet, username)
	rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))
	rfc2865.FramedIPAddress_Set(packet, net.ParseIP(ip))
	if sessionTime > 0 {
		rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(sessionTime))
	}

	radius.Exchange(context.Background(), packet, "127.0.0.1:1813")
	os.Exit(0)
}

// kernelModuleHint returns the distro-appropriate command to install the full
// kernel modules (needed for the PPP/L2TP modules on minimal/cloud kernels).
func kernelModuleHint() string {
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	switch {
	case exists("/usr/bin/dnf") || exists("/bin/dnf"):
		return "dnf install kernel-modules-extra"
	case exists("/usr/bin/apt-get") || exists("/bin/apt-get"):
		return "apt install linux-image-amd64   (Debian)   |   apt install linux-modules-extra-$(uname -r)   (Ubuntu)"
	case exists("/usr/bin/zypper"):
		return "zypper install kernel-default-extra"
	case exists("/usr/bin/pacman"):
		return "install/boot a kernel that ships the ppp modules (linux, linux-lts)"
	default:
		return "install the full kernel-modules package for your distro"
	}
}

var stdinReader = bufio.NewReader(os.Stdin)

// isTerminal reports whether stdin is an interactive terminal (so we can prompt).
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// confirm asks a yes/no question. Non-interactive input returns the default.
func confirm(prompt string, defaultYes bool) bool {
	if !isTerminal() {
		return defaultYes
	}
	hint := "[y/N]"
	if defaultYes {
		hint = "[Y/n]"
	}
	fmt.Printf("%s %s ", prompt, hint)
	line, _ := stdinReader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return defaultYes
	}
	return line == "y" || line == "yes"
}

// setupBackend provisions the host/kernel prerequisites for the VPN backend
// (loads + persists kernel modules, enables IP forwarding). It is the in-binary
// replacement for the host-prep half of setup-vpn-backend.sh, and is idempotent.
func setupBackend() {
	if os.Geteuid() != 0 {
		fmt.Println("setup must be run as root (or via sudo).")
		os.Exit(1)
	}
	var coreService service.CoreService
	fmt.Println("Provisioning VPN backend (kernel modules, IP forwarding)...")
	fmt.Println()
	for _, step := range coreService.Provision() {
		status := "OK  "
		if !step.OK {
			status = "FAIL"
		}
		fmt.Printf("  [%s] %s — %s\n", status, step.Name, step.Msg)
	}
	fmt.Println()

	// Missing kernel modules (typical of minimal/cloud kernels) block L2TP/PPTP
	// — offer to install the full kernel modules package, with consent.
	missing := coreService.MissingKernelModules()
	if len(missing) > 0 {
		fmt.Printf("Missing kernel modules: %s\n", strings.Join(missing, ", "))
		fmt.Println("These are required for L2TP/PPTP (OpenVPN is unaffected).")

		pkg := service.KernelModulesPackage()
		if pkg == "" {
			fmt.Printf("Fix manually: %s\n", kernelModuleHint())
			return
		}
		if !confirm(fmt.Sprintf("Install '%s' to provide them?", pkg), true) {
			fmt.Printf("Skipped. Install it later with: %s\n", kernelModuleHint())
			return
		}

		fmt.Printf("Installing %s (this can take a minute)...\n", pkg)
		installed, still, err := coreService.InstallKernelModules()
		if err != nil {
			fmt.Printf("  Install failed: %v\n", err)
			fmt.Printf("  Try manually: %s\n", kernelModuleHint())
			os.Exit(1)
		}
		if len(still) == 0 {
			fmt.Printf("  Installed %s and loaded the modules — no reboot needed.\n", installed)
		} else {
			fmt.Printf("  Installed %s. A reboot is required to load: %s\n", installed, strings.Join(still, ", "))
			fmt.Println("  (The modules load automatically on boot — no need to re-run setup.)")
			if confirm("Reboot now?", false) {
				fmt.Println("Rebooting...")
				if err := exec.Command("systemctl", "reboot").Run(); err != nil {
					_ = exec.Command("reboot").Run()
				}
				return
			}
			fmt.Println("Reboot when convenient to finish enabling L2TP/PPTP.")
		}
	}

	fmt.Println("VPN backend provisioning complete.")
}

// main is the entry point of the 3x-ui application.
// It parses command-line arguments to run the web server, migrate database, or update settings.
func main() {
	if len(os.Args) < 2 {
		runWebServer()
		return
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	settingCmd := flag.NewFlagSet("setting", flag.ExitOnError)
	var port int
	var username string
	var password string
	var webBasePath string
	var listenIP string
	var getListen bool
	var webCertFile string
	var webKeyFile string
	var tgbottoken string
	var tgbotchatid string
	var enabletgbot bool
	var tgbotRuntime string
	var reset bool
	var show bool
	var getCert bool
	var resetTwoFactor bool
	settingCmd.BoolVar(&reset, "reset", false, "Reset all settings")
	settingCmd.BoolVar(&show, "show", false, "Display current settings")
	settingCmd.IntVar(&port, "port", 0, "Set panel port number")
	settingCmd.StringVar(&username, "username", "", "Set login username")
	settingCmd.StringVar(&password, "password", "", "Set login password")
	settingCmd.StringVar(&webBasePath, "webBasePath", "", "Set base path for Panel")
	settingCmd.StringVar(&listenIP, "listenIP", "", "set panel listenIP IP")
	settingCmd.BoolVar(&resetTwoFactor, "resetTwoFactor", false, "Reset two-factor authentication settings")
	settingCmd.BoolVar(&getListen, "getListen", false, "Display current panel listenIP IP")
	settingCmd.BoolVar(&getCert, "getCert", false, "Display current certificate settings")
	settingCmd.StringVar(&webCertFile, "webCert", "", "Set path to public key file for panel")
	settingCmd.StringVar(&webKeyFile, "webCertKey", "", "Set path to private key file for panel")
	settingCmd.StringVar(&tgbottoken, "tgbottoken", "", "Set token for Telegram bot")
	settingCmd.StringVar(&tgbotRuntime, "tgbotRuntime", "", "Set cron time for Telegram bot notifications")
	settingCmd.StringVar(&tgbotchatid, "tgbotchatid", "", "Set chat ID for Telegram bot notifications")
	settingCmd.BoolVar(&enabletgbot, "enabletgbot", false, "Enable notifications via Telegram bot")

	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("    run            run web panel")
		fmt.Println("    migrate        migrate form other/old x-ui")
		fmt.Println("    setting        set settings")
		fmt.Println("    setup          provision the VPN backend (kernel modules, sysctl)")
	}

	flag.Parse()
	if showVersion {
		fmt.Println(config.GetVersion())
		return
	}

	switch os.Args[1] {
	case "run":
		err := runCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		runWebServer()
	case "migrate":
		migrateDb()
	case "setting":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		if reset {
			if err = resetSetting(); err != nil {
				return
			}
		} else {
			if err = updateSetting(port, username, password, webBasePath, listenIP, resetTwoFactor); err != nil {
				return
			}
		}
		if show {
			showSetting(show)
		}
		if getListen {
			GetListenIP(getListen)
		}
		if getCert {
			GetCertificate(getCert)
		}
		if (tgbottoken != "") || (tgbotchatid != "") || (tgbotRuntime != "") {
			updateTgbotSetting(tgbottoken, tgbotchatid, tgbotRuntime)
		}
		if enabletgbot {
			updateTgbotEnableSts(enabletgbot)
		}
	case "cert":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		if reset {
			updateCert("", "")
		} else {
			updateCert(webCertFile, webKeyFile)
		}
	case "openvpn-auth":
		openvpnAuth()
	case "openvpn-connect":
		openvpnConnect()
	case "openvpn-disconnect":
		openvpnDisconnect()
	case "setup":
		setupBackend()
	default:
		fmt.Println("Invalid subcommands")
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
	}
}
