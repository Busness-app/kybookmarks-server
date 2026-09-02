package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Busness-app/kybookmarks-server/internal/api"
	"github.com/Busness-app/kybookmarks-server/internal/audit"
	"github.com/Busness-app/kybookmarks-server/internal/devices"
	"github.com/Busness-app/kybookmarks-server/internal/sso"
	"github.com/Busness-app/kybookmarks-server/internal/store"
	"github.com/Busness-app/kybookmarks-server/internal/vault"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5869"
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
	legacyAuditSecret := os.Getenv("HMAC_SECRET")

	// No default: an unset SYNC_SECRET disables the directory sync webhook rather
	// than authenticating it with a value published in this repository.
	syncSecret := os.Getenv("SYNC_SECRET")
	if syncSecret == "" {
		log.Println("SYNC_SECRET is not set: /api/sync/events will reject all requests")
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	dbStore, err := store.NewStore(dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer dbStore.Close()

	vaultMgr := vault.NewManager(dbStore)
	deviceStore := devices.NewStore(dbStore)
	ssoStore := sso.NewStore(filepath.Join(dataDir, "config"))

	auditLogger, err := audit.NewLogger(filepath.Join(dataDir, "audit"), configDir, legacyAuditSecret)
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}

	cfg := api.Config{
		WebDir:     webDir,
		DataDir:    dataDir,
		SyncSecret: syncSecret,
	}

	srv := api.NewServer(dbStore, vaultMgr, deviceStore, ssoStore, auditLogger, cfg)

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
