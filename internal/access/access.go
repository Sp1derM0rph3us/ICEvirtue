// Package access is the single role-to-permission policy used by routes and pages.
package access

type Permission string

const (
	Viewer                 = "viewer"
	Operator               = "operator"
	Admin                  = "admin"
	Read        Permission = "read"
	Write       Permission = "write"
	ManageUsers Permission = "manage_users"
	ReadLogs    Permission = "read_logs"
)

func ValidRole(role string) bool { return role == Viewer || role == Operator || role == Admin }

func Allows(role string, permission Permission) bool {
	if !ValidRole(role) {
		return false
	}
	switch permission {
	case Read:
		return true
	case Write:
		return role == Operator || role == Admin
	case ManageUsers, ReadLogs:
		return role == Admin
	default:
		return false
	}
}
