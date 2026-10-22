package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpaqueMigrationDisablesLegacyAndChangesAreAtomic(t *testing.T) {
	if err := OpenDB(filepath.Join(t.TempDir(), "chat.db")); err != nil {
		t.Fatal(err)
	}
	defer DB.Close()
	if err := RegisterUser("sample-user", "synthetic-legacy-password"); err != nil {
		t.Fatal(err)
	}
	version, err := CheckOpaqueMigration("sample-user", "synthetic-legacy-password")
	if err != nil {
		t.Fatal(err)
	}
	backup := map[string]interface{}{"v": 1, "marker": "encrypted-identity-one"}
	if err := MigrateOpaqueAccount("sample-user", "wrong-version", "record-one", backup); err == nil {
		t.Fatal("stale migration version accepted")
	}
	account, err := GetOpaqueAccount("sample-user")
	if err != nil || account != nil {
		t.Fatal("failed migration changed account")
	}
	if err := MigrateOpaqueAccount("sample-user", version, "record-one", backup); err != nil {
		t.Fatal(err)
	}
	valid, err := ValidateUser("sample-user", "synthetic-legacy-password")
	if err != nil || valid {
		t.Fatal("legacy login remained available after migration")
	}
	if err := MigrateOpaqueAccount("sample-user", version, "record-again", backup); err == nil {
		t.Fatal("migration replay accepted")
	}
	newBackup := map[string]interface{}{"v": 1, "marker": "encrypted-identity-two"}
	if err := ReplaceOpaqueAccount("sample-user", 1, "record-two", newBackup); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceOpaqueAccount("sample-user", 1, "stale-record", backup); err == nil {
		t.Fatal("stale password change accepted")
	}
	account, err = GetOpaqueAccount("sample-user")
	if err != nil || account.Generation != 2 || account.Record != "record-two" || account.Backup["marker"] != "encrypted-identity-two" {
		t.Fatal("record and backup were not updated as one version")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ReplaceOpaqueAccount("sample-user", 2, "expired-record", backup, ctx); err == nil {
		t.Fatal("cancelled password change committed")
	}
	if err := CreateOpaqueAccount("expired-user", "expired-record", backup, ctx); err == nil {
		t.Fatal("cancelled registration committed")
	}
	exists, err := UserExists("expired-user")
	if err != nil || exists {
		t.Fatal("cancelled registration created a user")
	}
	account, err = GetOpaqueAccount("sample-user")
	if err != nil || account.Generation != 2 || account.Record != "record-two" {
		t.Fatal("cancelled change altered an existing account")
	}
}

func TestOpaqueSetupPersistsAndMissingSetupFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chat.db")
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	first, err := GetOrCreateOpaqueSetup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	DB.Close()
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	second, err := GetOrCreateOpaqueSetup(context.Background())
	if err != nil || first != second {
		t.Fatal("setup changed on reopen")
	}
	if err := CreateOpaqueAccount("sample-user", "sample-record", map[string]interface{}{"v": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec("DELETE FROM opaque_meta WHERE key='setup_v1'"); err != nil {
		t.Fatal(err)
	}
	DB.Close()
	if err := OpenDB(path); err == nil {
		DB.Close()
		t.Fatal("missing setup was silently replaced")
	}
}
