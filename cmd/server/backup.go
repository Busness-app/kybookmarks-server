package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kybookmarks-server/internal/api"
	"github.com/Busness-app/kybookmarks-server/internal/audit"
	"github.com/Busness-app/kybookmarks-server/internal/backup"
	"github.com/Busness-app/kybookmarks-server/internal/store"
)

// runBudget bounds one backup run; the lib's own upload budget is 15 minutes.
const runBudget = 16 * time.Minute

// openForBackup opens the store and the audit chain the way serve does, without listening.
func openForBackup() (*store.Store, *audit.Logger, api.Config) {
	e, err := loadEnv()
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.NewStore(e.cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	al, err := audit.NewLogger(filepath.Join(e.cfg.DataDir, "audit"), e.cfg.ConfigDir, e.legacyAuditSecret)
	if err != nil {
		st.Close()
		log.Fatalf("Failed to open audit chain: %v", err)
	}
	return st, al, e.cfg
}

func runBackupDrill() {
	st, _, cfg := openForBackup()
	defer st.Close()
	ctx := context.Background()
	res, err := backup.RunDrill(ctx, st, cfg.DataDir, cfg.ConfigDir, cfg.AppVersion)
	if err != nil {
		log.Fatalf("drill: %v", err)
	}
	for _, c := range res.Checks {
		fmt.Printf("%-5t %s %s\n", c.Passed, c.Name, c.Message)
	}
	if !res.Passed {
		os.Exit(1)
	}
}

// runExportCapsule writes the sealed capsule to out. Nothing that opens it is printed.
func runExportCapsule(out string) {
	st, _, cfg := openForBackup()
	defer st.Close()
	key, err := recoveryclient.LoadRecoveryKey(cfg.DataDir, backup.Settings(st))
	if err != nil {
		log.Fatalf("recovery key: %v", err)
	}
	payload, err := backup.Collect(context.Background(), st, cfg.DataDir, cfg.ConfigDir, cfg.AppVersion)
	if err != nil {
		log.Fatalf("collect: %v", err)
	}
	raw, m, err := recoveryclient.Seal(payload, key)
	if err != nil {
		log.Fatalf("seal: %v", err)
	}
	if err := os.WriteFile(out, raw, 0600); err != nil {
		log.Fatalf("write %s: %v", out, err)
	}
	fmt.Printf("capsule %s (%d bytes) sealed to key %s -> %s\n", m.CapsuleID, len(raw), m.RecoveryKeyID, out)
}

func runDeposit() {
	st, al, cfg := openForBackup()
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), runBudget)
	defer cancel()
	client := recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})
	res, err := runOnce(ctx, st, cfg, client)
	recordRun(al, "cli", res, err)
	if err != nil {
		os.Exit(1)
	}
}

// runOnce seals the instance once and delivers it everywhere it is configured to go.
func runOnce(ctx context.Context, st *store.Store, cfg api.Config, client recoveryclient.Depositor) (recoveryclient.Result, error) {
	sealer, err := backup.NewSealer(cfg.DeploymentKey)
	if err != nil {
		return recoveryclient.Result{}, err
	}
	rc := backup.RunConfig(cfg.DataDir, cfg.Backup.Dir, cfg.Backup.Keep, cfg.AppVersion, sealer)
	return recoveryclient.Run(ctx, rc, backup.Settings(st), func() (recoveryclient.Payload, error) {
		return backup.Collect(ctx, st, cfg.DataDir, cfg.ConfigDir, cfg.AppVersion)
	}, client)
}

// recordRun puts the run on the audit chain and the log, success or failure. The audit
// write is not the caller's to cancel; the chain applies its own deadline.
func recordRun(al *audit.Logger, actor string, res recoveryclient.Result, err error) {
	action, outcome, details := recoveryclient.Outcome(res, err)
	if _, aerr := al.Log(context.Background(), action, actor, "", "", backup.AuditDetails(details)+" outcome="+outcome); aerr != nil {
		log.Printf("audit: %s was NOT recorded: %v", action, aerr)
	}
	if err != nil {
		log.Printf("backup (%s): %s", actor, recoveryclient.AuditSafe(err.Error()))
		return
	}
	log.Printf("backup (%s): capsule %s (%d bytes) local=%q deposited=%t", actor, res.Manifest.CapsuleID, res.SizeBytes, res.LocalPath, res.Receipt != nil)
}

// backupLoop polls the admin's schedule once a minute; a change in the UI needs no restart.
// Silence is correct only when nothing was ever configured.
func backupLoop(ctx context.Context, st *store.Store, cfg api.Config, al *audit.Logger) {
	client := recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		next, on, err := recoveryclient.NextRun(cfg.Backup.DepositInterval, backup.Settings(st))
		if err != nil {
			log.Printf("backup: schedule unreadable: %s", recoveryclient.AuditSafe(err.Error()))
			continue
		}
		if !on || time.Now().Before(next) {
			continue
		}
		runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runBudget)
		res, err := runOnce(runCtx, st, cfg, client)
		cancel()
		if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrNoDestination) {
			continue
		}
		recordRun(al, "system", res, err)
	}
}

func runRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "path to the .kycap file")
	to := fs.String("to", "", "empty directory to restore into")
	service := fs.String("service", backup.AppName, "expected service name in the manifest")
	_ = fs.Parse(args)
	if *capsulePath == "" || *to == "" {
		fs.Usage()
		os.Exit(2)
	}
	shares, err := recoveryclient.ReadShares(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	if err := restore(*capsulePath, *to, *service, shares, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// restore is the one function in this server allowed to open a capsule sealed to the suite
// key; internal/backup/nodecrypt_test.go pins that.
func restore(capsulePath, targetDir, expectService string, shares []string, stdout io.Writer) error {
	return recoveryclient.Restore(capsulePath, targetDir, expectService, shares, stdout)
}
