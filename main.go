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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
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

// initLogger initializes the logger at the configured level. It is shared by the
// web server and by CLI subcommands (e.g. `setup`) that call into services which
// log — without it those services dereference the package's nil logger and panic.
func initLogger() {
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
}

// runWebServer initializes and starts the web server for the 3x-ui panel.
func runWebServer() {
	log.Printf("Starting %v %v", config.GetName(), config.GetVersion())

	initLogger()

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
// ovpnLeaseBlockIP implements the OpenVPN side of the per-account "User Limit"
// block allocation. When the panel has published blocks-<proto>/<CN> for this
// inbound (User Limit K>=2), it leases the lowest free IP inside that account's
// block and returns (ip, serverBlockMask, false) for a `ifconfig-push`. Returns
// ("","",false) for K==1 inbounds (no block file) — the caller keeps the pool IP.
//
// When the block is full the User Limit Strategy decides: "accept" force-kills the
// account's oldest device via the management socket and reuses its IP (returns that
// ip); "reject" (default) returns ("","",true) so the caller fails the connect and
// OpenVPN refuses the device.
//
// "Free" = not currently held by an established client (OpenVPN's own status
// file, authoritative) and not held by a fresh lease (a short-TTL marker that
// bridges the gap between this connect and the client appearing in the status
// file). Leaked leases self-expire, so no long-lived bookkeeping is needed.
func ovpnLeaseBlockIP(inboundId int, username, poolIP string) (string, string, bool) {
	proto := "udp"
	if strings.HasPrefix(poolIP, "10.3.") {
		proto = "tcp"
	}
	dir := fmt.Sprintf("/etc/openvpn/server-%d", inboundId)
	blockFile := filepath.Join(dir, "blocks-"+proto, username)
	data, err := os.ReadFile(blockFile)
	if err != nil {
		return "", "", false // no block published -> K==1, keep the pool IP
	}
	parts := strings.Fields(strings.TrimSpace(string(data)))
	if len(parts) < 2 {
		return "", "", false
	}
	// Block file format: "<serverBlockMask> <ip1> <ip2> ..." — the account's K
	// device IPs (an explicit list, so the block size need not be a power of two).
	mask := parts[0]
	candidates := parts[1:]

	statusPath := fmt.Sprintf("/var/run/openvpn/status-%d-%s.log", inboundId, proto)
	inUse := ovpnStatusIPs(statusPath)

	leaseDir := filepath.Join(dir, "leases-"+proto)
	_ = os.MkdirAll(leaseDir, 0755)
	now := time.Now()
	if entries, e := os.ReadDir(leaseDir); e == nil {
		for _, ent := range entries {
			p := filepath.Join(leaseDir, ent.Name())
			fi, se := os.Stat(p)
			if se != nil {
				continue
			}
			if now.Sub(fi.ModTime()) > 30*time.Second {
				os.Remove(p) // stale gap-lease
				continue
			}
			inUse[ent.Name()] = true // lease file is named by the leased IP
		}
	}

	for _, ip := range candidates {
		if inUse[ip] {
			continue
		}
		_ = os.WriteFile(filepath.Join(leaseDir, ip), []byte(username), 0644)
		return ip, mask, false
	}

	// Block full (device cap reached). "accept": admit this device by reusing the
	// oldest existing device's IP and disconnecting THAT device; "reject": refuse.
	if ovpnReadStrategy(dir, proto) == "accept" {
		// Capture the victim's client-ID here, while only the existing devices hold
		// the block IPs (this new client is not in the status yet). We reuse the
		// victim's IP for this client, so once it connects two clients share that IP
		// briefly — killing by the pre-captured CID disconnects the OLD one, not the
		// one we just admitted.
		victimIP, victimRAddr := ovpnOldestFromStatus(statusPath, candidates)
		if victimIP == "" {
			victimIP = candidates[0] // status not yet populated -> evict the first slot
		}
		// The kill MUST happen AFTER this hook returns: client-connect runs
		// synchronously and blocks OpenVPN's management event loop, so a kill issued
		// from here would deadlock. Hand it to a detached helper (openvpn-evict).
		ovpnSpawnEvict(inboundId, proto, victimIP, victimRAddr)
		_ = os.WriteFile(filepath.Join(leaseDir, victimIP), []byte(username), 0644)
		return victimIP, mask, false
	}
	return "", "", true // reject the new device
}

// ovpnReadStrategy returns the inbound's User Limit Strategy ("accept", else the
// default "reject") from the panel-published strategy-<proto> file.
func ovpnReadStrategy(dir, proto string) string {
	data, err := os.ReadFile(filepath.Join(dir, "strategy-"+proto))
	if err != nil {
		return "reject"
	}
	if strings.TrimSpace(string(data)) == "accept" {
		return "accept"
	}
	return "reject"
}

// ovpnOldestFromStatus reads the OpenVPN status-version 3 FILE and returns the
// virtual IP and client-ID (among ips) of the client connected longest, or ("","")
// if none appear yet. The connect hook uses the file (not the live management
// socket) to pick the eviction victim, because while the hook runs OpenVPN's
// management loop is blocked (see openvpnEvict).
func ovpnOldestFromStatus(statusPath string, ips []string) (ip, raddr string) {
	want := make(map[string]bool, len(ips))
	for _, w := range ips {
		want[w] = true
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return "", ""
	}
	bestSince := int64(1) << 62
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CLIENT_LIST\t") {
			continue
		}
		// status v3: [2]RealAddr [3]VirtualAddr [8]ConnectedSince(time_t)
		f := strings.Split(line, "\t")
		if len(f) <= 8 || !want[f[3]] {
			continue
		}
		if since, perr := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); perr == nil && since < bestSince {
			bestSince, ip, raddr = since, f[3], strings.TrimSpace(f[2])
		}
	}
	return ip, raddr
}

// ovpnSpawnEvict launches a detached `openvpn-evict` helper that disconnects the
// victim client once OpenVPN is servicing its management socket again. Fire-and-
// forget: the connect hook must not wait on it. raddr is the victim's real address
// (IP:port — the unambiguous per-client kill key); ip is the fallback when the
// status file had no entry yet.
func ovpnSpawnEvict(inboundId int, proto, ip, raddr string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "openvpn-evict", strconv.Itoa(inboundId), proto, ip, raddr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survive the hook exiting
	_ = cmd.Start()                                       // no Wait — detached
}

// openvpnEvict runs detached from the (synchronous, management-blocking) client-
// connect hook. It waits for that hook to return so OpenVPN resumes servicing its
// management socket, then disconnects the victim via `kill <real-address>` (the
// classic per-client kill — `client-kill <CID>` only applies to deferred-auth
// clients). The new client reuses the victim's VIRTUAL IP, but real addresses are
// unique, so this hits the old device, not the one just admitted. Falls back to the
// OLDEST client on <ip> when no real address was pre-captured.
// Usage: x-ui openvpn-evict <id> <proto> <ip> [real-address]
func openvpnEvict() {
	if len(os.Args) < 5 {
		return
	}
	inboundId, _ := strconv.Atoi(os.Args[2])
	proto := os.Args[3]
	targetIP := os.Args[4]
	raddr := ""
	if len(os.Args) >= 6 {
		raddr = os.Args[5]
	}
	time.Sleep(1500 * time.Millisecond) // let the connect hook return first

	sock := fmt.Sprintf("/var/run/openvpn/mgmt-%d-%s.sock", inboundId, proto)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if raddr == "" {
		// No pre-captured real address: query live and pick the OLDEST client on
		// targetIP (min connected-since) so the just-admitted client (newest) is
		// never the one killed when two share the virtual IP.
		if _, err := fmt.Fprint(conn, "status 3\n"); err != nil {
			return
		}
		bestSince := int64(1) << 62
		for {
			line, rerr := reader.ReadString('\n')
			if s := strings.TrimRight(line, "\r\n"); s != "" {
				if strings.HasPrefix(s, "CLIENT_LIST\t") {
					f := strings.Split(s, "\t")
					if len(f) > 8 && f[3] == targetIP {
						if since, perr := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); perr == nil && since < bestSince {
							bestSince, raddr = since, strings.TrimSpace(f[2])
						}
					}
				}
				if s == "END" {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
	}
	if raddr == "" {
		return
	}
	fmt.Fprintf(conn, "kill %s\n", raddr)
	// Read past the management greeting / async lines until the kill verdict so the
	// command is flushed and processed before we close the socket.
	for i := 0; i < 20; i++ {
		line, rerr := reader.ReadString('\n')
		s := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(s, "SUCCESS") || strings.HasPrefix(s, "ERROR") {
			break
		}
		if rerr != nil {
			break
		}
	}
}

// ovpnStatusIPs parses an OpenVPN status-version 3 file and returns the set of
// virtual (tunnel) IPs currently held by connected clients.
func ovpnStatusIPs(statusPath string) map[string]bool {
	set := map[string]bool{}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return set
	}
	for _, line := range strings.Split(string(data), "\n") {
		// CLIENT_LIST<TAB>CommonName<TAB>RealAddr<TAB>VirtualAddr<TAB>...
		if !strings.HasPrefix(line, "CLIENT_LIST\t") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) > 3 && f[3] != "" {
			set[f[3]] = true
		}
	}
	return set
}

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

	// User Limit K>=2: if the panel published a block for this account, lease a
	// free IP inside it and push it to this device (duplicate-cn lets K devices
	// share the CN). os.Args[3] is OpenVPN's writable per-session config file.
	leased, mask, reject := ovpnLeaseBlockIP(inboundId, username, ip)
	if reject {
		// User Limit reached with strategy=reject: a non-zero exit from a
		// client-connect script makes OpenVPN refuse this device.
		fmt.Fprintln(os.Stderr, "user limit reached; rejecting client")
		os.Exit(1)
	}
	if leased != "" {
		if len(os.Args) >= 4 && os.Args[3] != "" {
			_ = os.WriteFile(os.Args[3], []byte(fmt.Sprintf("ifconfig-push %s %s\n", leased, mask)), 0644)
		}
		ip = leased
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
	case "openvpn-evict":
		openvpnEvict()
	default:
		fmt.Println("Invalid subcommands")
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
	}
}
