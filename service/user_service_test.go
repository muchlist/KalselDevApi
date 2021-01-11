package service

import (
	"fmt"
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

type MockDao struct {
	mock.Mock
}

func (m *MockDao) InsertUser(user dto.UserRequest) (*string, rest_err.APIError) {
	args := m.Called(user)
	return args.Get(0).(*string), args.Error(1).(rest_err.APIError)
}

func (m *MockDao) GetUserByEmailWithPassword(email string) (*dto.User, rest_err.APIError) {
	args := m.Called(email)
	return args.Get(0).(*dto.User), args.Error(1).(rest_err.APIError)
}

func (m *MockDao) CheckEmailAvailable(email string) (bool, rest_err.APIError) {
	args := m.Called(email)
	return args.Get(0).(bool), args.Error(1).(rest_err.APIError)
}

func (m *MockDao) EditUser(userEmail string, userRequest dto.UserEditRequest) (*dto.UserResponse, rest_err.APIError) {
	args := m.Called(userEmail, userRequest)
	return args.Get(0).(*dto.UserResponse), args.Error(1).(rest_err.APIError)
}

func (m *MockDao) DeleteUser(userEmail string) rest_err.APIError {
	args := m.Called(userEmail)
	return args.Error(0).(rest_err.APIError)
}

func (m *MockDao) PutAvatar(email string, avatar string) (*dto.UserResponse, rest_err.APIError) {
	args := m.Called(email, avatar)
	return args.Get(0).(*dto.UserResponse), args.Error(1).(rest_err.APIError)
}

func (m *MockDao) ChangePassword(data dto.UserChangePasswordRequest) rest_err.APIError {
	args := m.Called(data)
	return args.Error(0).(rest_err.APIError)
}

func (m *MockDao) GetUserByID(userID primitive.ObjectID) (*dto.UserResponse, rest_err.APIError) {
	args := m.Called(userID)

	var res *dto.UserResponse = nil
	if args.Get(0) != nil {
		res = args.Get(0).(*dto.UserResponse)
	}

	var err rest_err.APIError = nil
	if args.Get(1) != nil {
		err = args.Get(1).(rest_err.APIError)
	}

	return res, err
}

func TestUserService_GetUserByID(t *testing.T) {

	objectID := primitive.NewObjectID()

	m := new(MockDao)
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

	m := new(MockDao)
	m.On("GetUserByID", objectID).Return(nil, rest_err.NewNotFoundError(fmt.Sprintf("User dengan ID %v tidak ditemukan", objectID.Hex())))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	user, err := service.GetUser(objectID)

	assert.Nil(t, user)
	assert.NotNil(t, err)
	assert.Equal(t, fmt.Sprintf("User dengan ID %v tidak ditemukan", objectID.Hex()), err.Message())
	assert.Equal(t, http.StatusNotFound, err.Status())
}

func (m *MockDao) GetUserByEmail(email string) (*dto.UserResponse, rest_err.APIError) {
	args := m.Called(email)

	var res *dto.UserResponse = nil
	if args.Get(0) != nil {
		res = args.Get(0).(*dto.UserResponse)
	}

	var err rest_err.APIError = nil
	if args.Get(1) != nil {
		err = args.Get(1).(rest_err.APIError)
	}
	return res, err
}

func TestUserService_GetUserByEmail_Found(t *testing.T) {

	email := "whois.muchlis@gmail.com"

	m := new(MockDao)
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

	m := new(MockDao)
	m.On("GetUserByEmail", email).Return(nil, rest_err.NewNotFoundError(fmt.Sprintf("User dengan Email %s tidak ditemukan", email)))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	user, err := service.GetUserByEmail(email)

	assert.Nil(t, user)
	assert.NotNil(t, err)
	assert.Equal(t, "User dengan Email whois.muchlis@gmail.com tidak ditemukan", err.Message())
	assert.Equal(t, http.StatusNotFound, err.Status())
}

func (m *MockDao) FindUser() (dto.UserResponseList, rest_err.APIError) {
	args := m.Called()

	var err rest_err.APIError = nil
	if args.Get(1) != nil {
		err = args.Get(1).(rest_err.APIError)
	}

	return args.Get(0).(dto.UserResponseList), err
}

func TestUserService_FindUsers(t *testing.T) {

	m := new(MockDao)
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
	m := new(MockDao)
	m.On("FindUser").Return(dto.UserResponseList(nil), rest_err.NewInternalServerError("Database error", nil))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	usersResult, err := service.FindUsers()

	assert.NotNil(t, err)
	assert.Equal(t, dto.UserResponseList(nil), usersResult)
	assert.Equal(t, "Database error", err.Message())
	assert.Equal(t, http.StatusInternalServerError, err.Status())
}
