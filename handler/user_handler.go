package handler

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/muchlist/KalselDevApi/dto"
	"github.com/muchlist/KalselDevApi/service"
	"github.com/muchlist/KalselDevApi/utils/mjwt"
	"github.com/muchlist/erru_utils_go/logger"
	"github.com/muchlist/erru_utils_go/rest_err"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"path/filepath"
)

func NewUserHandler(userService service.UserServiceInterface) *userHandler {
	return &userHandler{
		service: userService,
	}
}

type userHandler struct {
	service service.UserServiceInterface
}

//Get menampilkan user berdasarkan ID (bukan email)
func (u *userHandler) Get(c *fiber.Ctx) error {
	userID, err := primitive.ObjectIDFromHex(c.Params("user_id"))
	if err != nil {
		apiErr := rest_err.NewBadRequestError("Format userID salah")
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	user, apiErr := u.service.GetUser(userID)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(user)
}

//GetProfile mengembalikan user yang sedang login
func (u *userHandler) GetProfile(c *fiber.Ctx) error {
	claims := c.Locals(mjwt.CLAIMS).(*mjwt.CustomClaim)

	user, apiErr := u.service.GetUserByEmail(claims.Identity)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(user)
}

//Insert menambahkan user
func (u *userHandler) Register(c *fiber.Ctx) error {

	var user dto.UserRequest
	if err := c.BodyParser(&user); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	if err := user.Validate(); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	insertID, apiErr := u.service.InsertUser(user)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	res := fiber.Map{"msg": fmt.Sprintf("Register berhasil, ID: %s", *insertID)}
	return c.JSON(res)
}

//Find menampilkan list user
func (u *userHandler) Find(c *fiber.Ctx) error {

	userList, apiErr := u.service.FindUsers()
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(fiber.Map{"users": userList})
}

//Edit mengedit user oleh admin
func (u *userHandler) Edit(c *fiber.Ctx) error {

	var user dto.UserEditRequest
	if err := c.BodyParser(&user); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	if err := user.Validate(); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	userEdited, apiErr := u.service.EditUser(c.Params("user_email"), user)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(userEdited)
}

//Delete menghapus user, idealnya melalui middleware is_admin
func (u *userHandler) Delete(c *fiber.Ctx) error {

	claims := c.Locals(mjwt.CLAIMS).(*mjwt.CustomClaim)
	emailParams := c.Params("user_email")

	if claims.Identity == emailParams {
		apiErr := rest_err.NewBadRequestError("Tidak dapat menghapus akun terkait (diri sendiri)!")
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	apiErr := u.service.DeleteUser(emailParams)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(fiber.Map{"msg": fmt.Sprintf("user %s berhasil dihapus", emailParams)})
}

//ChangePassword mengganti password pada user sendiri
func (u *userHandler) ChangePassword(c *fiber.Ctx) error {

	claims := c.Locals(mjwt.CLAIMS).(*mjwt.CustomClaim)

	var user dto.UserChangePasswordRequest
	if err := c.BodyParser(&user); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	if err := user.Validate(); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	//mengganti user email dengan user aktif
	user.Email = claims.Identity

	apiErr := u.service.ChangePassword(user)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(fiber.Map{"msg": "Password berhasil diubah!"})
}

//ResetPassword mengganti password oleh admin pada user tertentu
func (u *userHandler) ResetPassword(c *fiber.Ctx) error {

	data := dto.UserChangePasswordRequest{
		Email:       c.Params("user_email"),
		NewPassword: "Password",
	}

	apiErr := u.service.ResetPassword(data)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(fiber.Map{"msg": fmt.Sprintf("Password user %s berhasil di reset!", c.Params("user_email"))})
}

//Login login
func (u *userHandler) Login(c *fiber.Ctx) error {

	var login dto.UserLoginRequest
	if err := c.BodyParser(&login); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	if err := login.Validate(); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	response, apiErr := u.service.Login(login)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(response)
}

//Login login
func (u *userHandler) RefreshToken(c *fiber.Ctx) error {

	var payload dto.UserRefreshTokenRequest
	if err := c.BodyParser(&payload); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	if err := payload.Validate(); err != nil {
		apiErr := rest_err.NewBadRequestError(err.Error())
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	response, apiErr := u.service.Refresh(payload)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(response)
}

//UploadImage melakukan pengambilan file menggunakan form "avatar" mengecek ekstensi dan memasukkannya ke database
//sesuai authorisasi aktif. File disimpan di folder static/images dengan nama file == jwt.identity alias email
func (u *userHandler) UploadImage(c *fiber.Ctx) error {

	claims := c.Locals(mjwt.CLAIMS).(*mjwt.CustomClaim)

	file, err := c.FormFile("avatar")
	if err != nil {
		apiErr := rest_err.NewAPIError("File gagal di upload", http.StatusBadRequest, "bad_request", []interface{}{err.Error()})
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	fileName := file.Filename
	fileExtension := filepath.Ext(fileName)
	if !(fileExtension == ".jpg" || fileExtension == ".png" || fileExtension == ".jpeg") {
		apiErr := rest_err.NewBadRequestError("Ektensi file tidak di support")
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	if file.Size > 2*1024*1024 { // 2 MB
		apiErr := rest_err.NewBadRequestError("Ukuran file terlalu besar")
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	path := "static/images/" + claims.Identity + fileExtension
	pathInDb := "images/" + claims.Identity + fileExtension

	err = c.SaveFile(file, path)
	if err != nil {
		logger.Error(fmt.Sprintf("%s gagal mengupload file", claims.Identity), err)
		apiErr := rest_err.NewInternalServerError("File gagal di upload", err)
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	usersResult, apiErr := u.service.PutAvatar(claims.Identity, pathInDb)
	if apiErr != nil {
		return c.Status(apiErr.Status()).JSON(apiErr)
	}

	return c.JSON(usersResult)
}
