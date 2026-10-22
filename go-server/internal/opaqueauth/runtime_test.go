package opaqueauth

import (
	"context"
	"strings"
	"testing"
)

func TestSharedCoreAuthenticatesAndRejectsWrongPassword(t *testing.T) {
	ctx := context.Background()
	invoke := func(request map[string]interface{}) map[string]interface{} {
		t.Helper()
		result, err := Call(ctx, request)
		if err != nil {
			t.Fatalf("shared OPAQUE operation failed: %v", err)
		}
		return result
	}
	password := "synthetic-test-password"
	username, serverID := "test-account", strings.Repeat("a", 64)
	setup := invoke(map[string]interface{}{"op": "server_setup"})["setup"]
	registration := invoke(map[string]interface{}{"op": "registration_start", "password": password})
	response := invoke(map[string]interface{}{"op": "registration_respond", "setup": setup, "username": username, "server_id": serverID, "request": registration["request"]})
	record := invoke(map[string]interface{}{"op": "registration_finish", "password": password, "state": registration["state"], "response": response["response"], "username": username, "server_id": serverID})
	validated := invoke(map[string]interface{}{"op": "record_validate", "record": record["record"]})
	for _, candidate := range []string{password, "synthetic-wrong-password"} {
		start := invoke(map[string]interface{}{"op": "login_start", "password": candidate})
		challenge := invoke(map[string]interface{}{"op": "login_respond", "setup": setup, "record": validated["record"], "username": username, "server_id": serverID, "request": start["request"]})
		finish, err := Call(ctx, map[string]interface{}{"op": "login_finish", "password": candidate, "state": start["state"], "response": challenge["response"], "username": username, "server_id": serverID})
		if candidate != password {
			if err == nil {
				t.Fatal("wrong password authenticated")
			}
			if strings.Contains(err.Error(), candidate) {
				t.Fatal("error exposed password")
			}
			continue
		}
		if err != nil {
			t.Fatal("correct password rejected")
		}
		verified := invoke(map[string]interface{}{"op": "login_verify", "state": challenge["state"], "finalization": finish["finalization"]})
		if finish["session_key"] != verified["session_key"] {
			t.Fatal("client and server session keys differ")
		}
		if finish["export_key"] != record["export_key"] {
			t.Fatal("client export key did not survive login")
		}
	}
}

func TestSharedCoreRejectsOversizedOrMalformedInput(t *testing.T) {
	for _, request := range []map[string]interface{}{
		{"op": "login_verify", "state": "not-base64", "finalization": "not-base64"},
		{"op": "login_start", "password": strings.Repeat("x", MaxMessageBytes+1)},
	} {
		if _, err := Call(context.Background(), request); err == nil {
			t.Fatal("malformed input accepted")
		}
	}
}
