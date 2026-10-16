package handlers

import "sync"

type groupOperationLock struct {
	mu   sync.Mutex
	refs int
}

var groupCatalogMu sync.RWMutex
var groupLocksMu sync.Mutex
var groupLocks = make(map[string]*groupOperationLock)

// Keep read/permission checks, mutations and notifications in one ordered
// operation for each group, without serializing unrelated groups. References
// include waiters; the last release removes the lock to avoid leaking group IDs.
func lockGroupOperation(msg map[string]interface{}) func() {
	groupCatalogMu.RLock()
	gid, _ := msg["gid"].(string)
	unlock := lockGroup(gid)
	return func() {
		defer groupCatalogMu.RUnlock()
		unlock()
	}
}

// lockGroup requires an existing catalog read lock, held until release. Taking
// that read lock twice would deadlock if a login snapshot has queued a writer.
func lockGroup(gid string) func() {
	if gid == "" {
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

// LockGroup is shared with history authorization and group snapshot publication.
func LockGroup(gid string) func() {
	return lockGroupOperation(map[string]interface{}{"gid": gid})
}
