package service

import (
	"fmt"
	"github.com/muchlist/KalselDevApi/dao"
	"github.com/muchlist/KalselDevApi/dto"
	"github.com/muchlist/KalselDevApi/utils/crypt"
	"github.com/muchlist/KalselDevApi/utils/mjwt"
	"github.com/muchlist/erru_utils_go/rest_err"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"testing"
	"time"
)

func TestUserService_GetUserByID(t *testing.T) {

	objectID := primitive.NewObjectID()

	m := new(dao.MockDao)
	m.On("GetUserByID", objectID).Return(&dto.UserResponse{
		ID:        objectID,
		Email:     "whois.muchlis@gmail.com",
		Name:      "muchlis",
		IsAdmin:   true,
		Avatar:    "",
		Timestamp: 1610350965,
	}, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	user, err := service.GetUser(objectID)

	assert.Nil(t, err)
	assert.Equal(t, "muchlis", user.Name)
	assert.Equal(t, "whois.muchlis@gmail.com", user.Email)
	assert.Equal(t, true, user.IsAdmin)
}

func TestUserService_GetUser_NoUserFound(t *testing.T) {
	objectID := primitive.NewObjectID()

	m := new(dao.MockDao)
	m.On("GetUserByID", objectID).Return(nil, rest_err.NewNotFoundError(fmt.Sprintf("User dengan ID %v tidak ditemukan", objectID.Hex())))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	user, err := service.GetUser(objectID)

	assert.Nil(t, user)
	assert.NotNil(t, err)
	assert.Equal(t, fmt.Sprintf("User dengan ID %v tidak ditemukan", objectID.Hex()), err.Message())
	assert.Equal(t, http.StatusNotFound, err.Status())
}

func TestUserService_GetUserByEmail_Found(t *testing.T) {

	email := "whois.muchlis@gmail.com"

	m := new(dao.MockDao)
	m.On("GetUserByEmail", email).Return(&dto.UserResponse{
		ID:        primitive.NewObjectID(),
		Email:     email,
		Name:      "Muchlis",
		IsAdmin:   true,
		Avatar:    "",
		Timestamp: time.Now().Unix(),
	}, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	user, err := service.GetUserByEmail(email)

	assert.Nil(t, err)
	assert.Equal(t, "Muchlis", user.Name)
	assert.Equal(t, "whois.muchlis@gmail.com", user.Email)
	assert.Equal(t, true, user.IsAdmin)
}

func TestUserService_GetUserByEmail_NotFound(t *testing.T) {

	email := "whois.muchlis@gmail.com"

	m := new(dao.MockDao)
	m.On("GetUserByEmail", email).Return(nil, rest_err.NewNotFoundError(fmt.Sprintf("User dengan Email %s tidak ditemukan", email)))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	user, err := service.GetUserByEmail(email)

	assert.Nil(t, user)
	assert.NotNil(t, err)
	assert.Equal(t, "User dengan Email whois.muchlis@gmail.com tidak ditemukan", err.Message())
	assert.Equal(t, http.StatusNotFound, err.Status())
}

func TestUserService_FindUsers(t *testing.T) {

	m := new(dao.MockDao)
	m.On("FindUser").Return(dto.UserResponseList{
		dto.UserResponse{
			ID:        primitive.NewObjectID(),
			Email:     "whois.muchlis@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   true,
			Avatar:    "",
			Timestamp: time.Now().Unix(),
		},
	}, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	usersResult, err := service.FindUsers()

	assert.Nil(t, err)
	assert.Equal(t, "Muchlis", usersResult[0].Name)
	assert.Equal(t, "whois.muchlis@gmail.com", usersResult[0].Email)
}

func TestUserService_FindUsers_errorDatabase(t *testing.T) {
	m := new(dao.MockDao)
	m.On("FindUser").Return(dto.UserResponseList(nil), rest_err.NewInternalServerError("Database error", nil))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	usersResult, err := service.FindUsers()

	assert.NotNil(t, err)
	assert.Equal(t, dto.UserResponseList(nil), usersResult)
	assert.Equal(t, "Database error", err.Message())
	assert.Equal(t, http.StatusInternalServerError, err.Status())
}

func TestUserService_InsertUser_Success(t *testing.T) {
	userInput := dto.UserRequest{
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   true,
		Avatar:    "",
		Password:  "password",
		Timestamp: time.Now().Unix(),
	}

	email := "whowho@gmail.com"
	idResp := "5f969f62259eae481fb0e856"

	m := new(dao.MockDao)
	m.On("InsertUser", mock.Anything).Return(&idResp, nil)
	m.On("CheckEmailAvailable", email).Return(true, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	insertedId, err := service.InsertUser(userInput)

	assert.Nil(t, err)
	assert.Equal(t, "5f969f62259eae481fb0e856", *insertedId)
}

func TestUserService_InsertUser_EmailNotAvailable(t *testing.T) {
	userInput := dto.UserRequest{
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   true,
		Avatar:    "",
		Password:  "password",
		Timestamp: time.Now().Unix(),
	}

	email := "whowho@gmail.com"
	idResp := "5f969f62259eae481fb0e856"

	m := new(dao.MockDao)
	m.On("InsertUser", mock.Anything).Return(&idResp, nil)
	m.On("CheckEmailAvailable", email).Return(false, rest_err.NewBadRequestError("Email tidak tersedia"))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	insertedId, err := service.InsertUser(userInput)

	assert.Nil(t, insertedId)
	assert.NotNil(t, err)
	assert.Equal(t, "Email tidak tersedia", err.Message())
	assert.Equal(t, 400, err.Status())
}
