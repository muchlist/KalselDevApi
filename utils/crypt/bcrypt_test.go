package crypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateHash(t *testing.T) {
	password := "password"
	passwordHash, err := Obj.GenerateHash(password)

	println(passwordHash)

	assert.Nil(t, err)
	assert.NotEqual(t, password, passwordHash)
}

func TestIsHashAndPasswordMatch(t *testing.T) {
	password := "password"
	hashpass := "$2a$04$Whst1LZo5bt9XaE/nCqJRehzQRcSG7nTP/sf3LVfNEEpWeLCJHlE6"

	match := Obj.IsPWAndHashPWMatch(password, hashpass)
	assert.EqualValues(t, true, match)
}

func TestIsHashAndPasswordNotMatch(t *testing.T) {
	password := "password"
	hashpass := "123454$9aJGmBBghpno5rOj9lhd7u6rCMwz8tvDxMsMx0xImil9iJMGt78ma"

	match := Obj.IsPWAndHashPWMatch(password, hashpass)
	assert.EqualValues(t, false, match)
}
