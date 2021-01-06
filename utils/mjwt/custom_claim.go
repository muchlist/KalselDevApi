package mjwt

import "time"

type CustomClaim struct {
	Identity  string
	Name      string
	Exp       int64
	TimeExtra time.Duration
	Jti       string
	IsAdmin   bool
}
