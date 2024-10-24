package config

import (
	"arch/internal/delivery/http/route"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/healthcheck"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/spf13/viper"
)

func NewFiber(route *route.RouteApp, config *viper.Viper) *fiber.App {
	var app = fiber.New(fiber.Config{
		AppName:           config.GetString("app.name"),
		ErrorHandler:      NewErrorHandler(),
		Prefork:           config.GetBool("web.prefork"),
		BodyLimit:         1024 * 1024 * 1024, // 1GB limit
		StreamRequestBody: true,
	})
	app.Use(recover.New(),
		compress.New(compress.Config{
			Level: compress.LevelBestSpeed,
		}),
		cors.New(cors.Config{
			AllowOrigins: "*",
			AllowHeaders: "Origin, Content-Type, Accept",
		}),
		healthcheck.New(),
		helmet.New(),
		requestid.New(),
		logger.New(logger.Config{
			Format:     "${locals:requestid} ${status} - ${method} ${path}\n",
			TimeFormat: "02-Jan-2006",
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
