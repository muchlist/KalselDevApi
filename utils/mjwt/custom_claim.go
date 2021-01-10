package mjwt

import (
	"time"
)

const (
	Access int = iota
	Refresh
)

type CustomClaim struct {
	Identity    string
	Name        string
	Exp         int64
	ExtraMinute time.Duration
	Type        int
	Fresh       bool
	IsAdmin     bool
}
