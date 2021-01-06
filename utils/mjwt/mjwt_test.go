package mjwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestJwtUtils_GenerateToken(t *testing.T) {
	c := CustomClaim{
		Identity:  "muchlis@gmail.com",
		IsAdmin:   true,
		Jti:       "",
		TimeExtra: 12,
	}

	signedToken, err := Obj.GenerateToken(c)

	assert.Nil(t, err)
	assert.NotEmpty(t, signedToken)
}

func TestJwtUtils_ValidateToken(t *testing.T) {
	c := CustomClaim{
		Identity:  "muchlis@gmail.com",
		IsAdmin:   true,
		Jti:       "",
		TimeExtra: 12,
	}

	signedToken, err := Obj.GenerateToken(c)
	assert.Nil(t, err)

	tokenValid, err := Obj.ValidateToken(signedToken)

	assert.Nil(t, err)
	assert.NotEmpty(t, tokenValid)
}

func TestJwtUtils_NotValidateToken(t *testing.T) {
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9XX.eyJleHAiOjE2MDM4MDcyMzEsImlkZW50aXR5IjoibXVjaGxpc0BnbWFpbC5jb20iLCJpc19hZG1pbiI6dHJ1ZSwianRpIjoiIn0.dzKZdhPFtF-YC6uh5JZqBv7mhBjGTz1_rgIP-sRbYrU"

	tokenValid, err := Obj.ValidateToken(invalidToken)

	assert.Empty(t, tokenValid)
	assert.NotNil(t, err)
	assert.Equal(t, "Token tidak valid", err.Message())
}

func TestJwtUtils_ExpiredValidateToken(t *testing.T) {
	c := CustomClaim{
		Identity:  "muchlis@gmail.com",
		IsAdmin:   true,
		Jti:       "",
		TimeExtra: -1,
	}

	signedToken, err := Obj.GenerateToken(c)
	assert.Nil(t, err)

	tokenValid, err := Obj.ValidateToken(signedToken)
	assert.Nil(t, tokenValid)

	assert.NotNil(t, err)
	assert.Equal(t, "Token tidak valid", err.Message())
}

func TestJwtUtils_ReadToken(t *testing.T) {
	c := CustomClaim{
		Identity:  "muchlis@gmail.com",
		IsAdmin:   true,
		Jti:       "",
		TimeExtra: 0,
	}
	signedToken, err := Obj.GenerateToken(c)
	assert.Nil(t, err)
	tokenValid, err := Obj.ValidateToken(signedToken)
	assert.Nil(t, err)
	claims, err := Obj.ReadToken(tokenValid)
	assert.Nil(t, err)

	assert.Equal(t, "muchlis@gmail.com", claims.Identity)
	assert.Equal(t, true, claims.IsAdmin)
	assert.Equal(t, time.Now().Unix(), claims.Exp)
	assert.Equal(t, "", claims.Jti)
}
