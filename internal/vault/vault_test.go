package vault

import (
	"os"
	"testing"
	"time"

	"kybookmarks-server/internal/store"
)

func TestVaultSyncAndCAS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	s, err := store.NewStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	account := &store.Account{
		ID:           "acc-1",
		Username:     "alice",
		Email:        "alice@example.com",
		DisplayName:  "Alice",
		PasswordHash: "dummy",
		AuthSalt:     "dummy",
	}
	if err := s.CreateAccount(account); err != nil {
		t.Fatal(err)
	}

	vm := NewManager(s)

	// 1. Initial sync create bookmark
	req1 := store.SyncRequest{
		KnownVersions: map[string]int64{},
		Changes: []store.VaultObject{
			{
				ObjectID:        "bm-1",
				ObjectType:      "bookmark",
				ParentID:        "",
				Version:         1,
				Position:        0,
				Ciphertext:      "encrypted-data-v1",
				Nonce:           "nonce-1",
				KeyWrapper:      "key-wrap-1",
				ProtocolVersion: 1,
			},
		},
	}

	resp1, err := vm.Sync(account.ID, req1)
	if err != nil {
		t.Fatalf("sync 1 failed: %v", err)
	}
	if len(resp1.UpdatedObjects) != 1 || resp1.UpdatedObjects[0].Version != 1 {
		t.Fatalf("expected 1 updated object with ver 1, got %v", resp1.UpdatedObjects)
	}

	// 2. Valid version upgrade
	req2 := store.SyncRequest{
		KnownVersions: map[string]int64{"bm-1": 1},
		Changes: []store.VaultObject{
			{
				ObjectID:        "bm-1",
				ObjectType:      "bookmark",
				ParentID:        "",
				Version:         2,
				Position:        0,
				Ciphertext:      "encrypted-data-v2",
				Nonce:           "nonce-2",
				KeyWrapper:      "key-wrap-1",
				ProtocolVersion: 1,
			},
		},
	}

	resp2, err := vm.Sync(account.ID, req2)
	if err != nil {
		t.Fatalf("sync 2 failed: %v", err)
	}
	if len(resp2.UpdatedObjects) != 1 || resp2.UpdatedObjects[0].Version != 2 {
		t.Fatalf("expected updated object with ver 2, got %v", resp2.UpdatedObjects)
	}

	// 3. Stale version write (expect conflict)
	req3 := store.SyncRequest{
		KnownVersions: map[string]int64{"bm-1": 1},
		Changes: []store.VaultObject{
			{
				ObjectID:        "bm-1",
				ObjectType:      "bookmark",
				ParentID:        "",
				Version:         2, // stale, server is already on 2!
				Position:        0,
				Ciphertext:      "stale-data",
				Nonce:           "nonce-stale",
				KeyWrapper:      "key-wrap-1",
				ProtocolVersion: 1,
			},
		},
	}

	resp3, err := vm.Sync(account.ID, req3)
	if err != nil {
		t.Fatalf("sync 3 failed: %v", err)
	}
	if len(resp3.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(resp3.Conflicts))
	}

	// 4. Verify history retained
	history, err := vm.GetObjectHistory(account.ID, "bm-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) < 2 {
		t.Fatalf("expected at least 2 history versions, got %d", len(history))
	}

	// 5. Test tombstone deletion
	delReq := store.SyncRequest{
		KnownVersions: map[string]int64{"bm-1": 2},
		Changes: []store.VaultObject{
			{
				ObjectID:        "bm-1",
				ObjectType:      "bookmark",
				Version:         3,
				Deleted:         true,
				Ciphertext:      "deleted-tombstone",
				Nonce:           "n-3",
				KeyWrapper:      "kw-1",
				ProtocolVersion: 1,
			},
		},
	}
	delResp, err := vm.Sync(account.ID, delReq)
	if err != nil {
		t.Fatalf("delete sync failed: %v", err)
	}
	if len(delResp.Tombstones) != 1 {
		t.Fatalf("expected 1 tombstone, got %d", len(delResp.Tombstones))
	}

	time.Sleep(10 * time.Millisecond)
}
