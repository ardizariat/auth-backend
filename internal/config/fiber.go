package config

import (
	"arch/internal/delivery/http/route"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/healthcheck"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/spf13/viper"
)

const idleTimeout = 5 * time.Second

func NewFiber(route *route.RouteApp, config *viper.Viper) *fiber.App {
	var app = fiber.New(fiber.Config{
		AppName:           config.GetString("app.name"),
		ErrorHandler:      NewErrorHandler(),
		Prefork:           config.GetBool("web.prefork"),
		BodyLimit:         1024 * 1024 * 1024, // 1GB limit
		ReadBufferSize:    8192,               // Set a higher value if needed
		StreamRequestBody: true,
		IdleTimeout:       idleTimeout,
	})

	app.Use(
		cors.New(
			cors.Config{
				AllowHeaders: strings.Join([]string{
					"Origin",
					"Content-Type",
					"Accept",
					"Content-Length",
					"Accept-Language",
					"Accept-Encoding",
					"Connection",
					"Access-Control-Allow-Origin",
					"Authorization",
				}, ","),
				AllowOrigins: strings.Join([]string{
					"http://localhost:3000",
					"http://localhost:7000",
					"http://localhost:7001",
					"http://localhost:6001",
					"http://localhost:9346",
					"https://dev-kpi.modernland.co.id",
					"https://dev-auth.modernland.co.id",
					"https://dev-api-auth.modernland.co.id",
					"https://dev-api-kpi.modernland.co.id",
				}, ","),
				AllowOriginsFunc: nil,
				AllowCredentials: false,
				AllowMethods: strings.Join([]string{
					fiber.MethodGet,
					fiber.MethodPost,
					fiber.MethodHead,
					fiber.MethodPut,
					fiber.MethodDelete,
					fiber.MethodPatch,
				}, ","),
				MaxAge: 3600,
			},
		),
		limiter.New(limiter.Config{
			Next: func(c *fiber.Ctx) bool {
				return c.IP() == "127.0.0.1" || c.IP() == "localhost"
			},
			Max:        20,
			Expiration: 30 * time.Second,
			KeyGenerator: func(c *fiber.Ctx) string {
				return c.Get("x-forwarded-for")
			},
		}),
		recover.New(),
		compress.New(compress.Config{
			Level: compress.LevelBestSpeed,
		}),
		healthcheck.New(),
		helmet.New(),
		requestid.New(),
		logger.New(logger.Config{
			Format: "${locals:requestid} ${time} ${status} - ${method} ${path}\n",
			// TimeFormat: "02-Jan-2006",
			TimeFormat: "15:04:05",
			TimeZone:   config.GetString("app.timezone"),
		}),
	)
	route.SetupRoutes(app)
	return app
}

func NewErrorHandler() fiber.ErrorHandler {
	return func(ctx *fiber.Ctx, err error) error {
		code := http.StatusInternalServerError
		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
		}
		return ctx.Status(code).JSON(fiber.Map{
			"message": err.Error(),
		})
	}
}
