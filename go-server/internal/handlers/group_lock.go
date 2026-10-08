package handlers

import "sync"

type groupOperationLock struct {
	mu   sync.Mutex
	refs int
}

var groupLocksMu sync.Mutex
var groupLocks = make(map[string]*groupOperationLock)

// Keep read/permission checks, mutations and notifications in one ordered
// operation for each group, without serializing unrelated groups. References
// include waiters; the last release removes the lock to avoid leaking group IDs.
func lockGroupOperation(msg map[string]interface{}) func() {
	gid, ok := msg["gid"].(string)
	if !ok || gid == "" {
		return func() {}
	}
	groupLocksMu.Lock()
	lock := groupLocks[gid]
	if lock == nil {
		lock = &groupOperationLock{}
		groupLocks[gid] = lock
	}
	lock.refs++
	groupLocksMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		groupLocksMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(groupLocks, gid)
		}
		groupLocksMu.Unlock()
	}
}
