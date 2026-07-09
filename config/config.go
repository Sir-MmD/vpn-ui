// Package config provides configuration management utilities for the vpn-ui panel,
// including version information, logging levels, database paths, and environment variable handling.
package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed version
var version string

//go:embed name
var name string

// LogLevel represents the logging level for the application.
type LogLevel string

// Logging level constants
const (
	Debug   LogLevel = "debug"
	Info    LogLevel = "info"
	Notice  LogLevel = "notice"
	Warning LogLevel = "warning"
	Error   LogLevel = "error"
)

// GetVersion returns the version string of the vpn-ui application.
func GetVersion() string {
	return strings.TrimSpace(version)
}

// GetName returns the name of the vpn-ui application.
func GetName() string {
	return strings.TrimSpace(name)
}

// GetLogLevel returns the current logging level based on environment variables or defaults to Info.
func GetLogLevel() LogLevel {
	if IsDebug() {
		return Debug
	}
	logLevel := os.Getenv("VPNUI_LOG_LEVEL")
	if logLevel == "" {
		return Info
	}
	return LogLevel(logLevel)
}

// IsDebug returns true if debug mode is enabled via the VPNUI_DEBUG environment variable.
func IsDebug() bool {
	return os.Getenv("VPNUI_DEBUG") == "true"
}

// GetBinFolderPath returns the path to the binary folder, defaulting to "bin" if not set via VPNUI_BIN_FOLDER.
func GetBinFolderPath() string {
	binFolderPath := os.Getenv("VPNUI_BIN_FOLDER")
	if binFolderPath == "" {
		binFolderPath = "bin"
	}
	return binFolderPath
}

func getBaseDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return "."
	}
	exeDir := filepath.Dir(exePath)
	exeDirLower := strings.ToLower(filepath.ToSlash(exeDir))
	if strings.Contains(exeDirLower, "/appdata/local/temp/") || strings.Contains(exeDirLower, "/go-build") {
		wd, err := os.Getwd()
		if err != nil {
			return "."
		}
		return wd
	}
	return exeDir
}

// GetDBFolderPath returns the folder that holds the database file. It defaults to
// the directory of the binary (overridable with VPNUI_DB_FOLDER) so a copied or
// moved install carries its data with it, rather than silently sharing a fixed
// /etc/vpn-ui. Legacy installs are migrated from LegacyDBPath on first init.
func GetDBFolderPath() string {
	dbFolderPath := os.Getenv("VPNUI_DB_FOLDER")
	if dbFolderPath != "" {
		return dbFolderPath
	}
	return getBaseDir()
}

// dbBaseName is the database file's base name (without extension). It is fixed
// rather than derived from GetName() so the on-disk DB is always "vpn-ui.db".
const dbBaseName = "vpn-ui"

// GetDBPath returns the full path to the database file (next to the binary).
func GetDBPath() string {
	return fmt.Sprintf("%s/%s.db", GetDBFolderPath(), dbBaseName)
}

// LegacyDBPaths lists previous database names next to the binary to migrate from
// on first init when the current DB doesn't exist yet:
//   - <bindir>/x-ui.db — the prior next-to-binary name (before the vpn-ui rename)
//
// It deliberately does NOT reach into /etc/vpn-ui — a DB left there is not adopted.
// The current GetDBPath is never included. Empty on a custom VPNUI_DB_FOLDER.
func LegacyDBPaths() []string {
	if os.Getenv("VPNUI_DB_FOLDER") != "" {
		return nil
	}
	current := GetDBPath()
	var out []string
	for _, p := range []string{
		fmt.Sprintf("%s/x-ui.db", GetDBFolderPath()),
	} {
		if p != current {
			out = append(out, p)
		}
	}
	return out
}

// GetLogFolder returns the path to the log folder based on environment variables or platform defaults.
func GetLogFolder() string {
	logFolderPath := os.Getenv("VPNUI_LOG_FOLDER")
	if logFolderPath != "" {
		return logFolderPath
	}
	return "/var/log/vpn-ui"
}

// DB migration (moving/renaming a legacy database to GetDBPath) is handled
// cross-platform by database.InitDB via config.LegacyDBPaths — see migrateLegacyDB.
