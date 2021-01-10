package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/muchlist/KalselDevApi/controller"
	"github.com/muchlist/KalselDevApi/dao"
	"github.com/muchlist/KalselDevApi/db"
	"github.com/muchlist/KalselDevApi/middleware"
	"github.com/muchlist/KalselDevApi/service"
	"github.com/muchlist/KalselDevApi/utils/crypt"
	"github.com/muchlist/KalselDevApi/utils/mjwt"
	"log"
)

var (
	//Utils
	cryptoUtils = crypt.NewCrypto()
	jwt         = mjwt.NewJwt()

	//Dao
	userDao = dao.NewUserDao()

	//Service
	userService = service.NewUserService(userDao, cryptoUtils, jwt)

	//Controller or Handler
	pingHandler = controller.NewPingHandler()
	userHandler = controller.NewUserHandler(userService)
)

func mapUrls(app *fiber.App) {
	app.Use(logger.New())
	app.Use(middleware.LimitRequest())

	app.Static("/images", "./static/images")

	api := app.Group("/api/v1")
	api.Get("/ping", pingHandler.Ping)
	api.Post("/users", userHandler.Register)
	api.Post("/login", userHandler.Login)
	api.Post("/refresh", userHandler.RefreshToken)

	apiAuth := app.Group("/api/v1")
	apiAuth.Use(middleware.AuthMiddleware)
	apiAuth.Get("/users", userHandler.Find)
}

func main() {

	// inisiasi database
	client, ctx, cancel := db.Init()
	defer client.Disconnect(ctx) //nolint:errcheck
	defer cancel()

	app := fiber.New()
	mapUrls(app)
	log.Fatal(app.Listen(":3500"))

}
