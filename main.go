package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/muchlist/KalselDevApi/controller"
	"github.com/muchlist/KalselDevApi/db"
	"github.com/muchlist/KalselDevApi/middleware"
	"log"
)

func mapUrls(app *fiber.App) {
	app.Use(logger.New())
	app.Use(middleware.LimitRequest())

	app.Static("/images", "./static/images")

	api := app.Group("/api/v1")
	api.Get("/ping", controller.Ping)
}

func main() {

	// inisiasi database
	client, ctx, cancel := db.Init()
	defer client.Disconnect(ctx) //nolint:errcheck
	defer cancel()

	app := fiber.New()
	mapUrls(app)
	log.Fatal(app.Listen(":3000"))

}
