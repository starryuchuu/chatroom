package database

import "time"

type PendingFriend struct {
	Requester, Target string
	Created           time.Time
}
type PendingInvite struct {
	GID, Target, Inviter string
	Created              time.Time
}

func SavePendingFriend(from, to string, created time.Time) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO pending_friend_requests VALUES(?,?,?)", from, to, float64(created.UnixNano())/1e9)
	return err
}
func DeletePendingFriend(from, to string) error {
	_, err := DB.Exec("DELETE FROM pending_friend_requests WHERE requester=? AND target=?", from, to)
	return err
}
func SavePendingInvite(gid, to, from string, created time.Time) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO pending_group_invites VALUES(?,?,?,?)", gid, to, from, float64(created.UnixNano())/1e9)
	return err
}
func DeletePendingInvite(gid, to string) error {
	_, err := DB.Exec("DELETE FROM pending_group_invites WHERE gid=? AND target=?", gid, to)
	return err
}
func LoadPendingRequests() ([]PendingFriend, []PendingInvite, error) {
	cutoff := float64(time.Now().Add(-24*time.Hour).UnixNano()) / 1e9
	if _, err := DB.Exec("DELETE FROM pending_friend_requests WHERE created_at<=?", cutoff); err != nil {
		return nil, nil, err
	}
	if _, err := DB.Exec("DELETE FROM pending_group_invites WHERE created_at<=?", cutoff); err != nil {
		return nil, nil, err
	}
	rows, err := DB.Query("SELECT requester,target,created_at FROM pending_friend_requests")
	if err != nil {
		return nil, nil, err
	}
	var friends []PendingFriend
	for rows.Next() {
		var f PendingFriend
		var at float64
		if err = rows.Scan(&f.Requester, &f.Target, &at); err != nil {
			rows.Close()
			return nil, nil, err
		}
		f.Created = time.Unix(0, int64(at*1e9))
		friends = append(friends, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = DB.Query("SELECT gid,target,inviter,created_at FROM pending_group_invites")
	if err != nil {
		return nil, nil, err
	}
	var invites []PendingInvite
	for rows.Next() {
		var f PendingInvite
		var at float64
		if err = rows.Scan(&f.GID, &f.Target, &f.Inviter, &at); err != nil {
			rows.Close()
			return nil, nil, err
		}
		f.Created = time.Unix(0, int64(at*1e9))
		invites = append(invites, f)
	}
	err = rows.Err()
	rows.Close()
	return friends, invites, err
}
