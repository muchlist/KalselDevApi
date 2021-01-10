package dao

import (
	"errors"
	"fmt"
	"github.com/muchlist/KalselDevApi/dto"
	"github.com/muchlist/erru_utils_go/logger"
	"github.com/muchlist/erru_utils_go/rest_err"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"context"

	"github.com/muchlist/KalselDevApi/db"
)

const (
	connectTimeout = 2

	keyUserColl = "user"

	keyID        = "_id"
	keyEmail     = "email"
	keyHashPw    = "hash_pw"
	keyName      = "name"
	keyIsAdmin   = "is_admin"
	keyAvatar    = "avatar"
	keyTimeStamp = "timestamp"
)

func NewUserDao() UserDaoInterface {
	return &userDao{}
}

type userDao struct {
}

type UserDaoInterface interface {
	InsertUser(user dto.UserRequest) (*string, rest_err.APIError)
	GetUserByID(userID primitive.ObjectID) (*dto.UserResponse, rest_err.APIError)
	GetUserByEmail(email string) (*dto.UserResponse, rest_err.APIError)
	GetUserByEmailWithPassword(email string) (*dto.User, rest_err.APIError)
	FindUser() (dto.UserResponseList, rest_err.APIError)
	CheckEmailAvailable(email string) (bool, rest_err.APIError)
	EditUser(userEmail string, userRequest dto.UserEditRequest) (*dto.UserResponse, rest_err.APIError)
	DeleteUser(userEmail string) rest_err.APIError
	PutAvatar(email string, avatar string) (*dto.UserResponse, rest_err.APIError)
	ChangePassword(data dto.UserChangePasswordRequest) rest_err.APIError
}

//InsertUser menambahkan user dan mengembalikan insertedID, err
func (u *userDao) InsertUser(user dto.UserRequest) (*string, rest_err.APIError) {

	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	insertDoc := bson.D{
		{keyName, user.Name},
		{keyEmail, strings.ToLower(user.Email)},
		{keyIsAdmin, user.IsAdmin},
		{keyAvatar, user.Avatar},
		{keyHashPw, user.Password},
		{keyTimeStamp, user.Timestamp},
	}

	result, err := coll.InsertOne(ctx, insertDoc)
	if err != nil {
		apiErr := rest_err.NewInternalServerError("Gagal menyimpan user ke database", err)
		logger.Error("Gagal menyimpan user ke database", err)
		return nil, apiErr
	}

	insertID := result.InsertedID.(primitive.ObjectID).Hex()

	return &insertID, nil
}

//GetUser mendapatkan user dari database berdasarkan userID, jarang digunakan
//pada case ini biasanya menggunakan email karena user yang digunakan adalah email
func (u *userDao) GetUserByID(userID primitive.ObjectID) (*dto.UserResponse, rest_err.APIError) {

	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	var user dto.UserResponse
	opts := options.FindOne()
	opts.SetProjection(bson.M{keyHashPw: 0})

	if err := coll.FindOne(ctx, bson.M{keyID: userID}, opts).Decode(&user); err != nil {

		if err == mongo.ErrNoDocuments {
			apiErr := rest_err.NewNotFoundError(fmt.Sprintf("User dengan ID %v tidak ditemukan", userID.Hex()))
			return nil, apiErr
		}

		logger.Error("gagal mendapatkan user (by ID) dari database", err)
		apiErr := rest_err.NewInternalServerError("Gagal mendapatkan user dari database", err)
		return nil, apiErr
	}

	return &user, nil
}

//GetUserByEmail mendapatkan user dari database berdasarkan email
func (u *userDao) GetUserByEmail(email string) (*dto.UserResponse, rest_err.APIError) {

	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	var user dto.UserResponse
	opts := options.FindOne()
	opts.SetProjection(bson.M{keyHashPw: 0})

	if err := coll.FindOne(ctx, bson.M{keyEmail: strings.ToLower(email)}, opts).Decode(&user); err != nil {

		if err == mongo.ErrNoDocuments {
			apiErr := rest_err.NewNotFoundError(fmt.Sprintf("User dengan Email %s tidak ditemukan", email))
			return nil, apiErr
		}

		logger.Error("gagal mendapatkan user (by email) dari database", err)
		apiErr := rest_err.NewInternalServerError("Gagal mendapatkan user dari database", err)
		return nil, apiErr
	}

	return &user, nil
}

//GetUserByEmail mendapatkan user dari database berdasarkan email dengan memunculkan passwordhash
//password hash digunakan pada endpoint login dan change password
func (u *userDao) GetUserByEmailWithPassword(email string) (*dto.User, rest_err.APIError) {

	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	var user dto.User

	if err := coll.FindOne(ctx, bson.M{keyEmail: strings.ToLower(email)}).Decode(&user); err != nil {

		if err == mongo.ErrNoDocuments {
			// karena sudah pasti untuk keperluan login maka error yang dikembalikan unauthorized
			apiErr := rest_err.NewUnauthorizedError("Username atau password tidak valid")
			return nil, apiErr
		}

		logger.Error("Gagal mendapatkan user dari database (GetUserByEmailWithPassword)", err)
		apiErr := rest_err.NewInternalServerError("Error pada database", errors.New("database error"))
		return nil, apiErr
	}

	return &user, nil
}

//FindUser mendapatkan daftar semua user dari database
func (u *userDao) FindUser() (dto.UserResponseList, rest_err.APIError) {

	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	users := dto.UserResponseList{}
	opts := options.Find()
	opts.SetSort(bson.D{{keyID, -1}})
	sortCursor, err := coll.Find(ctx, bson.M{}, opts)
	if err != nil {
		logger.Error("Gagal mendapatkan user dari database", err)
		apiErr := rest_err.NewInternalServerError("Database error", err)
		return dto.UserResponseList{}, apiErr
	}

	if err = sortCursor.All(ctx, &users); err != nil {
		logger.Error("Gagal decode usersCursor ke objek slice", err)
		apiErr := rest_err.NewInternalServerError("Database error", err)
		return dto.UserResponseList{}, apiErr
	}

	return users, nil
}

//CheckEmailAvailable melakukan pengecekan apakah alamat email sdh terdaftar di database
//jika ada akan return false ,yang artinya email tidak available
func (u *userDao) CheckEmailAvailable(email string) (bool, rest_err.APIError) {

	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	opts := options.FindOne()
	opts.SetProjection(bson.M{keyID: 1})

	var user dto.UserResponse

	if err := coll.FindOne(ctx, bson.M{keyEmail: strings.ToLower(email)}, opts).Decode(&user); err != nil {

		if err == mongo.ErrNoDocuments {
			return true, nil
		}

		logger.Error("Gagal mendapatkan user dari database", err)
		apiErr := rest_err.NewInternalServerError("Gagal mendapatkan user dari database", err)
		return false, apiErr
	}

	apiErr := rest_err.NewBadRequestError("Email tidak tersedia")
	return false, apiErr
}

//EditUser mengubah user, memerlukan timestamp int64 agar lebih safety pada saat pengeditan oleh dua user
func (u *userDao) EditUser(userEmail string, userRequest dto.UserEditRequest) (*dto.UserResponse, rest_err.APIError) {
	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	opts := options.FindOneAndUpdate()
	opts.SetReturnDocument(1)

	filter := bson.M{
		keyEmail:     userEmail,
		keyTimeStamp: userRequest.TimestampFilter,
	}
	update := bson.M{
		"$set": bson.M{
			keyName:      userRequest.Name,
			keyIsAdmin:   userRequest.IsAdmin,
			keyTimeStamp: time.Now().Unix(),
		},
	}

	var user dto.UserResponse
	if err := coll.FindOneAndUpdate(ctx, filter, update, opts).Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, rest_err.NewBadRequestError("User tidak diupdate karena ID atau timestamp tidak valid")
		}

		logger.Error("Gagal mendapatkan user dari database", err)
		apiErr := rest_err.NewInternalServerError("Gagal mendapatkan user dari database", err)
		return nil, apiErr
	}

	return &user, nil
}

//DeleteUser menghapus user
func (u *userDao) DeleteUser(userEmail string) rest_err.APIError {
	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	filter := bson.M{
		keyEmail: userEmail,
	}

	result, err := coll.DeleteOne(ctx, filter)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return rest_err.NewBadRequestError("User gagal dihapus, dokumen tidak ditemukan")
		}

		logger.Error("Gagal menghapus user dari database", err)
		apiErr := rest_err.NewInternalServerError("Gagal mendapatkan user dari database", err)
		return apiErr
	}

	if result.DeletedCount == 0 {
		return rest_err.NewBadRequestError("User gagal dihapus, dokumen tidak ditemukan")
	}

	return nil
}

//PutAvatar hanya mengubah avatar berdasarkan filter email
func (u *userDao) PutAvatar(email string, avatar string) (*dto.UserResponse, rest_err.APIError) {
	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	opts := options.FindOneAndUpdate()
	opts.SetReturnDocument(1)

	filter := bson.M{
		keyEmail: email,
	}
	update := bson.M{
		"$set": bson.M{
			keyAvatar:    avatar,
			keyTimeStamp: time.Now().Unix(),
		},
	}

	var user dto.UserResponse
	if err := coll.FindOneAndUpdate(ctx, filter, update, opts).Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, rest_err.NewBadRequestError(fmt.Sprintf("User avatar gagal diupload, user dengan email %s tidak ditemukan", email))
		}

		logger.Error("Gagal mendapatkan user dari database", err)
		apiErr := rest_err.NewInternalServerError("Gagal mendapatkan user dari database", err)
		return nil, apiErr
	}

	return &user, nil
}

//ChangePassword merubah hash_pw dengan password baru sesuai masukan
func (u *userDao) ChangePassword(data dto.UserChangePasswordRequest) rest_err.APIError {
	coll := db.Db.Collection(keyUserColl)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()

	filter := bson.M{
		keyEmail: data.Email,
	}

	update := bson.M{
		"$set": bson.M{
			keyHashPw:    data.NewPassword,
			keyTimeStamp: time.Now().Unix(),
		},
	}

	result, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return rest_err.NewBadRequestError("Penggantian password gagal, email salah")
		}

		logger.Error("Gagal mendapatkan user dari database (ChangePassword)", err)
		apiErr := rest_err.NewInternalServerError("Gagal mengganti password user", err)
		return apiErr
	}

	if result.ModifiedCount == 0 {
		return rest_err.NewBadRequestError("Penggantian password gagal, kemungkinan email salah")
	}

	return nil
}
