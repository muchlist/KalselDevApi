package app

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/muchlist/KalselDevApi/middleware"
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

	api.Get("/users", middleware.AuthMiddleware, userHandler.Find)
	api.Get("/profile", middleware.AuthMiddleware, userHandler.GetProfile)
}
