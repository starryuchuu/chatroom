package handlers

import (
	"net"
	"sync"
	"time"
)

const authFailureLimit = 5
const authWindow = time.Minute
const authConcurrency = 4

var authLimitsMu sync.Mutex
var authFailures = make(map[string][]time.Time)
var authInFlight int
var authIPInFlight = make(map[string]int)

func authIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// Reserve before any expensive password hashing. Success never erases recent
// failures; one account cannot reset another account's budget on a shared IP.
func reserveAuth(ip string, now time.Time) bool {
	authLimitsMu.Lock()
	defer authLimitsMu.Unlock()
	for host, failures := range authFailures {
		recent := failures[:0]
		for _, at := range failures {
			if now.Sub(at) < authWindow {
				recent = append(recent, at)
			}
		}
		if len(recent) == 0 {
			delete(authFailures, host)
		} else {
			authFailures[host] = recent
		}
	}
	if len(authFailures[ip])+authIPInFlight[ip] >= authFailureLimit || authInFlight >= authConcurrency {
		return false
	}
	authInFlight++
	authIPInFlight[ip]++
	return true
}

func releaseAuth(ip string, failed bool) {
	authLimitsMu.Lock()
	defer authLimitsMu.Unlock()
	authInFlight--
	authIPInFlight[ip]--
	if authIPInFlight[ip] == 0 {
		delete(authIPInFlight, ip)
	}
	if failed {
		authFailures[ip] = append(authFailures[ip], time.Now())
	}
}
