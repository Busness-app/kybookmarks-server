package main

import (
	"strings"
	"testing"
	"time"
)

func TestBackupConfigFromEnv(t *testing.T) {
	t.Setenv("KYBOOKMARKS_BACKUP_DIR", "/tmp/x")
	t.Setenv("KYBOOKMARKS_BACKUP_KEEP", "3")
	t.Setenv("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL", "1h")
	t.Setenv("KYBOOKMARKS_BACKUP_ALLOW_PRIVATE_RECOVERY", "true")
	cfg, err := loadBackupConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dir != "/tmp/x" || cfg.Keep != 3 || cfg.DepositInterval != time.Hour || !cfg.AllowPrivateRecovery {
		t.Fatalf("%+v", cfg)
	}
}

func TestBackupConfigRefusesKeepBelowOneAndShortInterval(t *testing.T) {
	t.Setenv("KYBOOKMARKS_BACKUP_KEEP", "0")
	if _, err := loadBackupConfig(); err == nil || !strings.Contains(err.Error(), "KYBOOKMARKS_BACKUP_KEEP") {
		t.Fatalf("keep=0: %v", err)
	}
	t.Setenv("KYBOOKMARKS_BACKUP_KEEP", "7")
	t.Setenv("KYBOOKMARKS_BACKUP_DEPOSIT_INTERVAL", "5m")
	if _, err := loadBackupConfig(); err == nil || !strings.Contains(err.Error(), "15m") {
		t.Fatalf("5m interval: %v", err)
	}
}
