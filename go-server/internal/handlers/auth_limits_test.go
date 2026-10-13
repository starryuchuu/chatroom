package handlers

import (
	"testing"
	"time"
)

func TestAuthenticationFailureBudgetExpiryAndConcurrency(t *testing.T) {
	authLimitsMu.Lock()
	authFailures = make(map[string][]time.Time)
	authInFlight = 0
	authIPInFlight = make(map[string]int)
	authLimitsMu.Unlock()
	now := time.Now()
	for i := 0; i < authFailureLimit; i++ {
		if !reserveAuth("ip", now) {
			t.Fatal("premature limit")
		}
		releaseAuth("ip", true)
		if i == 1 {
			if !reserveAuth("ip", now) {
				t.Fatal("successful login blocked early")
			}
			releaseAuth("ip", false)
		}
	}
	if reserveAuth("ip", now) {
		releaseAuth("ip", false)
		t.Fatal("success erased prior failure budget")
	}
	if !reserveAuth("ip", now.Add(authWindow+time.Second)) {
		t.Fatal("failure limit never expires")
	}
	releaseAuth("ip", false)
	for i := 0; i < authConcurrency; i++ {
		if !reserveAuth("another", time.Now()) {
			t.Fatal("early concurrency rejection")
		}
	}
	if reserveAuth("another", time.Now()) {
		releaseAuth("another", false)
		t.Fatal("unbounded authentication concurrency")
	}
	for i := 0; i < authConcurrency; i++ {
		releaseAuth("another", false)
	}
}
