package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/muchlist/erru_utils_go/rest_err"
	"net/http"
	"time"
)

func LimitRequest() fiber.Handler {
	return limiter.New(limiter.Config{
		Next: func(c *fiber.Ctx) bool {
			return c.IP() == "127.0.0.1"
		},
		Max:        30,
		Expiration: 1 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(http.StatusTooManyRequests).JSON(rest_err.NewAPIError("terlalu banyak request", http.StatusTooManyRequests, "rate_limiter", []interface{}{"too many requests in a given amount of time"}))
		},
	})
}
