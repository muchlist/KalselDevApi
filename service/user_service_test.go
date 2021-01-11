package service

import (
	"errors"
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

func TestUserService_InsertUser_DBError(t *testing.T) {
	userInput := dto.UserRequest{
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   true,
		Avatar:    "",
		Password:  "password",
		Timestamp: time.Now().Unix(),
	}

	email := "whowho@gmail.com"

	m := new(dao.MockDao)
	m.On("InsertUser", mock.Anything).Return(nil, rest_err.NewInternalServerError("Gagal menyimpan user ke database", errors.New("db error")))
	m.On("CheckEmailAvailable", email).Return(true, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	insertedId, err := service.InsertUser(userInput)

	assert.Nil(t, insertedId)
	assert.NotNil(t, err)
	assert.Equal(t, "Gagal menyimpan user ke database", err.Message())
	assert.Equal(t, 500, err.Status())
}

func TestUserService_EditUser(t *testing.T) {
	email := "whowho@gmail.com"
	userInput := dto.UserEditRequest{
		Name:            "Muchlis",
		IsAdmin:         false,
		TimestampFilter: 0,
	}

	m := new(dao.MockDao)
	m.On("EditUser", email, userInput).Return(&dto.UserResponse{
		ID:        primitive.ObjectID{},
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   false,
		Avatar:    "",
		Timestamp: 0,
	}, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	userResponse, err := service.EditUser(email, userInput)

	assert.Nil(t, err)
	assert.Equal(t, "Muchlis", userResponse.Name)
}

func TestUserService_EditUser_TimeStampNotmatch(t *testing.T) {

	email := "whowho@gmail.com"
	userInput := dto.UserEditRequest{
		Name:            "Muchlis",
		IsAdmin:         false,
		TimestampFilter: 0,
	}

	m := new(dao.MockDao)
	m.On("EditUser", email, userInput).Return(nil, rest_err.NewBadRequestError("User tidak diupdate karena ID atau timestamp tidak valid"))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())

	userResponse, err := service.EditUser(email, userInput)

	assert.Nil(t, userResponse)
	assert.NotNil(t, err)
	assert.Equal(t, "User tidak diupdate karena ID atau timestamp tidak valid", err.Message())
	assert.Equal(t, 400, err.Status())
}

func TestUserService_DeleteUser(t *testing.T) {
	email := "whowho@gmail.com"

	m := new(dao.MockDao)
	m.On("DeleteUser", email).Return(nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	err := service.DeleteUser("whowho@gmail.com")

	assert.Nil(t, err)
}

func TestUserService_DeleteUser_Failed(t *testing.T) {
	email := "whowho@gmail.com"

	m := new(dao.MockDao)
	m.On("DeleteUser", email).Return(rest_err.NewBadRequestError("User gagal dihapus, dokumen tidak ditemukan"))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	err := service.DeleteUser("whowho@gmail.com")

	assert.NotNil(t, err)
	assert.Equal(t, "User gagal dihapus, dokumen tidak ditemukan", err.Message())
}

func TestUserService_Login(t *testing.T) {

	userRequest := dto.UserLoginRequest{
		Email:    "whowho@gmail.com",
		Password: "Password",
	}

	m := new(dao.MockDao)
	m.On("GetUserByEmailWithPassword", userRequest.Email).Return(&dto.User{
		ID:        primitive.ObjectID{},
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   false,
		Avatar:    "",
		HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
		Timestamp: 0,
	}, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	userResult, err := service.Login(userRequest)

	assert.Nil(t, err)
	assert.NotNil(t, userRequest)
	assert.Equal(t, "Muchlis", userResult.Name)
	assert.NotEmpty(t, userResult.AccessToken)
	assert.NotEmpty(t, userResult.RefreshToken)
}

func TestUserService_Login_WrongPassword(t *testing.T) {
	userRequest := dto.UserLoginRequest{
		Email:    "whowho@gmail.com",
		Password: "salahPassword",
	}

	m := new(dao.MockDao)
	m.On("GetUserByEmailWithPassword", userRequest.Email).Return(&dto.User{
		ID:        primitive.ObjectID{},
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   false,
		Avatar:    "",
		HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
		Timestamp: 0,
	}, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	userResult, err := service.Login(userRequest)

	assert.Nil(t, userResult)
	assert.NotNil(t, err)
	assert.Equal(t, "Username atau password tidak valid", err.Message())
}

func TestUserService_Login_UserNotFound(t *testing.T) {
	userRequest := dto.UserLoginRequest{
		Email:    "notexist@gmail.com",
		Password: "salahPassword",
	}

	m := new(dao.MockDao)
	m.On("GetUserByEmailWithPassword", userRequest.Email).Return(nil, rest_err.NewUnauthorizedError("Username atau password tidak valid"))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	userResult, err := service.Login(userRequest)

	assert.Nil(t, userResult)
	assert.NotNil(t, err)
	assert.Equal(t, "Username atau password tidak valid", err.Message())
	assert.Equal(t, 401, err.Status())
}

func TestUserService_PutAvatar(t *testing.T) {

	email := "whowhos@gmail.com"
	filePath := "images/whowhos@gmail.com.jpg"

	m := new(dao.MockDao)
	m.On("PutAvatar", email, filePath).Return(&dto.UserResponse{
		ID:        primitive.ObjectID{},
		Email:     "whowhos@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   false,
		Avatar:    "images/whowhos@gmail.com.jpg",
		Timestamp: 0,
	}, nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	userResult, err := service.PutAvatar("whowhos@gmail.com", "images/whowhos@gmail.com.jpg")

	assert.Nil(t, err)
	assert.Equal(t, "images/whowhos@gmail.com.jpg", userResult.Avatar)
}

func TestUserService_PutAvatar_UserNotFound(t *testing.T) {

	email := "whowhos@gmail.com"
	filePath := "images/whowhos@gmail.com.jpg"

	m := new(dao.MockDao)
	m.On("PutAvatar", email, filePath).Return(nil, rest_err.NewBadRequestError(fmt.Sprintf("User avatar gagal diupload, user dengan email %s tidak ditemukan", email)))

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	userResult, err := service.PutAvatar("whowhos@gmail.com", "images/whowhos@gmail.com.jpg")

	assert.Nil(t, userResult)
	assert.NotNil(t, err)
	assert.Equal(t, "User avatar gagal diupload, user dengan email whowhos@gmail.com tidak ditemukan", err.Message())
}

func TestUserService_ChangePassword_Success(t *testing.T) {
	data := dto.UserChangePasswordRequest{
		Email:       "whowho@gmail.com",
		Password:    "Password",
		NewPassword: "NewPassword",
	}

	m := new(dao.MockDao)
	m.On("GetUserByEmailWithPassword", mock.Anything).Return(&dto.User{
		ID:        primitive.ObjectID{},
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   false,
		Avatar:    "",
		HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
		Timestamp: 0,
	}, nil)
	m.On("ChangePassword", mock.Anything).Return(nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	err := service.ChangePassword(data)

	assert.Nil(t, err)
}

func TestUserService_ChangePassword_FailPasswordSame(t *testing.T) {

	data := dto.UserChangePasswordRequest{
		Email:       "whowho@gmail.com",
		Password:    "Password",
		NewPassword: "Password",
	}
	m := new(dao.MockDao)
	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	err := service.ChangePassword(data)

	assert.NotNil(t, err)
	assert.Equal(t, "Gagal mengganti password, password tidak boleh sama dengan sebelumnya!", err.Message())
}

func TestUserService_ChangePassword_OldPasswordWrong(t *testing.T) {

	data := dto.UserChangePasswordRequest{
		Email:       "whowho@gmail.com",
		Password:    "salahPassword",
		NewPassword: "NewPassword",
	}

	m := new(dao.MockDao)
	m.On("GetUserByEmailWithPassword", mock.Anything).Return(&dto.User{
		ID:        primitive.ObjectID{},
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   false,
		Avatar:    "",
		HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
		Timestamp: 0,
	}, nil)
	m.On("ChangePassword", mock.Anything).Return(nil)

	service := NewUserService(m, crypt.NewCrypto(), mjwt.NewJwt())
	err := service.ChangePassword(data)

	assert.NotNil(t, err)
	assert.Equal(t, "Gagal mengganti password, password salah!", err.Message())
}
