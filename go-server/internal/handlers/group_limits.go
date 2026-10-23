package handlers

import (
	"chatroom/internal/e2ee"
	"github.com/google/uuid"
)

// The group catalog and the E2EE envelope must agree on the number of people
// who can receive a message. The owner counts towards this limit.
const maxGroupMembers = e2ee.MaxRecipients
const groupCapacityError = "群聊最多支持256位成员"

func uniqueGroupMembers(members []string) []string {
	seen := make(map[string]bool, len(members))
	unique := make([]string, 0, len(members))
	for _, member := range members {
		if !seen[member] {
			seen[member] = true
			unique = append(unique, member)
		}
	}
	return unique
}

// Only generated UUID group identifiers are suitable for default logs. Reject
// arbitrary request fields instead of allowing control characters or topics.
func groupLogID(value string) string {
	if len(value) == 36 && uuid.Validate(value) == nil {
		return value
	}
	return "invalid"
}
