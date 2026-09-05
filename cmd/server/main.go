package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/api"
	"github.com/Busness-app/kybookmarks-server/internal/audit"
	"github.com/Busness-app/kybookmarks-server/internal/backup"
	"github.com/Busness-app/kybookmarks-server/internal/devices"
	"github.com/Busness-app/kybookmarks-server/internal/sso"
	"github.com/Busness-app/kybookmarks-server/internal/store"
	"github.com/Busness-app/kybookmarks-server/internal/vault"
)

// appVersion is recorded in every capsule manifest; bump with releases.
const appVersion = "0.2.0"

// loadBackupConfig reads the KYBOOKMARKS_BACKUP_* variables. Keep below one and an
// interval under the lib's floor are refused here, at startup, not at the first backup.
func loadBackupConfig() (api.BackupConfig, error) {
	cfg := api.BackupConfig{Dir: os.Getenv("KYBOOKMARKS_BACKUP_DIR"), Keep: 7, DepositInterval: 24 * time.Hour}
	if v := os.Getenv("KYBOOKMARKS_BACKUP_KEEP"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return cfg, fmt.Errorf("KYBOOKMARKS_BACKUP_KEEP: must be an integer of at least 1, got %q", v)
		}
		cfg.Keep = n
	}
	if v := os.Getenv("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL: %w", err)
		}
		if d != 0 && d < recoveryclient.MinInterval {
			return cfg, fmt.Errorf("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL: %s is below the 15m floor (0 disables)", v)
		}
		cfg.DepositInterval = d
	}
	cfg.AllowPrivateRecovery = strings.EqualFold(os.Getenv("KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY"), "true")
	return cfg, nil
}

// env is what every subcommand reads from the environment.
type env struct {
	port              string
	webDir            string
	legacyAuditSecret string
	cfg               api.Config
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		case "backup-drill":
			runBackupDrill()
			return
		case "export-capsule":
			runExportCapsule(argOr(2, backup.AppName+".kycap"))
			return
		case "deposit":
			runDeposit()
			return
		case "restore":
			runRestore(os.Args[2:])
			return
		default:
			fmt.Fprintln(os.Stderr, "usage: kybookmarks-server [serve|backup-drill|export-capsule <out>|deposit|restore -capsule <file> -to <dir> [-service <name>]]")
			os.Exit(2)
		}
	}
	serve()
}

func argOr(i int, def string) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return def
}

// loadEnv reads every variable the server and the backup subcommands share, and mints the
// deployment key if this is the first run.
func loadEnv() (env, error) {
	e := env{port: os.Getenv("PORT")}
	if e.port == "" {
		e.port = "5869"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	webDir := os.Getenv("WEB_DIR")
	if webDir == "" {
		// check if frontend/dist exists
		if _, err := os.Stat("./frontend/dist"); err == nil {
			webDir = "./frontend/dist"
		} else if _, err := os.Stat("./dist"); err == nil {
			webDir = "./dist"
		}
	}

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "./config"
	}

	// HMAC_SECRET only verifies audit entries written before the chain was keyed.
	// The live chain key comes from AUDIT_KEY or CONFIG_DIR/audit.key; see internal/audit.
	e.legacyAuditSecret = os.Getenv("HMAC_SECRET")

	// No default: an unset SYNC_SECRET disables the directory sync webhook rather
	// than authenticating it with a value published in this repository.
	syncSecret := os.Getenv("SYNC_SECRET")

	backupCfg, err := loadBackupConfig()
	if err != nil {
		return e, err
	}
	deploymentKey, err := keyfile.LoadOrCreate(filepath.Join(configDir, "deployment.key"), 32)
	if err != nil {
		return e, fmt.Errorf("deployment key: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return e, fmt.Errorf("failed to create data directory: %w", err)
	}

	e.webDir = webDir
	e.cfg = api.Config{
		WebDir:        webDir,
		DataDir:       dataDir,
		ConfigDir:     configDir,
		SyncSecret:    syncSecret,
		Backup:        backupCfg,
		DeploymentKey: deploymentKey,
		AppVersion:    appVersion,
	}
	return e, nil
}

func serve() {
	e, err := loadEnv()
	if err != nil {
		log.Fatal(err)
	}
	if e.cfg.SyncSecret == "" {
		log.Println("SYNC_SECRET is not set: /api/sync/events will reject all requests")
	}
	if e.cfg.Backup.AllowPrivateRecovery {
		log.Println("KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY is on: private and CGNAT KyRecovery destinations admitted (HTTPS still required)")
	}
	cfg, port, webDir, dataDir := e.cfg, e.port, e.webDir, e.cfg.DataDir

	dbStore, err := store.NewStore(dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer dbStore.Close()

	vaultMgr := vault.NewManager(dbStore)
	deviceStore := devices.NewStore(dbStore)
	ssoStore := sso.NewStore(filepath.Join(dataDir, "config"))

	auditLogger, err := audit.NewLogger(filepath.Join(dataDir, "audit"), cfg.ConfigDir, e.legacyAuditSecret)
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}

	srv, err := api.NewServer(dbStore, vaultMgr, deviceStore, ssoStore, auditLogger, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	loopCtx, stopLoop := context.WithCancel(context.Background())
	defer stopLoop()
	go backupLoop(loopCtx, dbStore, cfg, auditLogger)

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      srv.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("KyBookmarks Server listening on port %s (webDir=%s, dataDir=%s)", port, webDir, dataDir)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down KyBookmarks Server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		fmt.Printf("Server forced shutdown: %v\n", err)
	}
	log.Println("KyBookmarks Server stopped cleanly.")
}
