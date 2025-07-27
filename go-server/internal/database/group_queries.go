package database

import (
	"chatroom/internal/models"
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"
)

// GetUserGroups 从数据库中检索用户所属的所有群组
func GetUserGroups(username string) ([]models.Group, error) {
	rows, err := DB.Query("SELECT gid, group_name, owner, members FROM groups")
	if err != nil {
		log.Printf("查询群组失败: %v", err)
		return nil, err
	}
	defer rows.Close()

	var userGroups []models.Group
	for rows.Next() {
		var g models.Group
		var membersJSON string
		if err := rows.Scan(&g.GID, &g.GroupName, &g.Owner, &membersJSON); err != nil {
			log.Printf("扫描群组行失败: %v", err)
			continue
		}

		var members []string
		if err := json.Unmarshal([]byte(membersJSON), &members); err != nil {
			log.Printf("解析群组成员JSON失败 (gid: %s): %v", g.GID, err)
			continue
		}
		g.Members = members

		// 检查用户是否是该群组的成员
		isMember := false
		for _, member := range g.Members {
			if member == username {
				isMember = true
				break
			}
		}

		if isMember {
			userGroups = append(userGroups, g)
		}

	}
	if err = rows.Err(); err != nil {
		log.Printf("遍历群组行时出错: %v", err)
		return nil, err
	}

	log.Printf("为用户 '%s' 找到了 %d 个群组", username, len(userGroups))
	return userGroups, nil
}

// GetGroup 从数据库中通过 GID 检索单个群组的信息
func GetGroup(gid string) (*models.Group, error) {
	row := DB.QueryRow("SELECT group_name, owner, members FROM groups WHERE gid = ?", gid)

	var g models.Group
	var membersJSON string
	if err := row.Scan(&g.GroupName, &g.Owner, &membersJSON); err != nil {
		log.Printf("扫描群组失败 (gid: %s): %v", gid, err)
		return nil, err // 包括 sql.ErrNoRows
	}

	var members []string
	if err := json.Unmarshal([]byte(membersJSON), &members); err != nil {
		log.Printf("解析群组成员JSON失败 (gid: %s): %v", gid, err)
		return nil, err
	}
	g.Members = members
	g.GID = gid

	return &g, nil
}

// CreateGroup 在数据库中创建一个新群组
func CreateGroup(groupName, owner string, members []string) (*models.Group, error) {
	// 使用 github.com/google/uuid 生成 GID
	gid := uuid.New().String()
	now := time.Now().Format("2006-01-02 15:04:05")

	membersJSON, err := json.Marshal(members)
	if err != nil {
		log.Printf("序列化群组成员失败: %v", err)
		return nil, err
	}

	stmt, err := DB.Prepare("INSERT INTO groups (gid, group_name, owner, members, created_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("准备创建群组语句失败: %v", err)
		return nil, err
	}
	defer stmt.Close()

	_, err = stmt.Exec(gid, groupName, owner, string(membersJSON), now)
	if err != nil {
		log.Printf("执行创建群组失败: %v", err)
		return nil, err
	}

	newGroup := &models.Group{
		GID:       gid,
		GroupName: groupName,
		Owner:     owner,
		Members:   members,
	}
	return newGroup, nil
}

// UpdateGroupMembers 更新群组成员列表
func UpdateGroupMembers(gid string, members []string) error {
	membersJSON, err := json.Marshal(members)
	if err != nil {
		log.Printf("序列化群组成员失败: %v", err)
		return err
	}

	stmt, err := DB.Prepare("UPDATE groups SET members=? WHERE gid=?")
	if err != nil {
		log.Printf("准备更新群组成员语句失败: %v", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(string(membersJSON), gid)
	if err != nil {
		log.Printf("执行更新群组成员失败: %v", err)
		return err
	}

	return nil
}

// DeleteGroup 从数据库中删除群组
func DeleteGroup(gid string) error {
	stmt, err := DB.Prepare("DELETE FROM groups WHERE gid=?")
	if err != nil {
		log.Printf("准备删除群组语句失败: %v", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(gid)
	if err != nil {
		log.Printf("执行删除群组失败: %v", err)
		return err
	}

	return nil
}

// UpdateGroupOwner 更新群组所有者
func UpdateGroupOwner(gid, newOwner string) error {
	stmt, err := DB.Prepare("UPDATE groups SET owner=? WHERE gid=?")
	if err != nil {
		log.Printf("准备更新群组所有者语句失败: %v", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(newOwner, gid)
	if err != nil {
		log.Printf("执行更新群组所有者失败: %v", err)
		return err
	}

	return nil
}

// UpdateGroupName 更新群组名称
func UpdateGroupName(gid, newName string) error {
	stmt, err := DB.Prepare("UPDATE groups SET group_name=? WHERE gid=?")
	if err != nil {
		log.Printf("准备更新群组名称语句失败: %v", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(newName, gid)
	if err != nil {
		log.Printf("执行更新群组名称失败: %v", err)
		return err
	}

	return nil
}
