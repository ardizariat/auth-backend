package route

import (
	"arch/internal/delivery/http/controller"
	"arch/internal/delivery/http/middleware"

	"github.com/gofiber/fiber/v2"
)

type RouteApp struct {
	AuthJwtMiddleware *middleware.AuthJwtMiddleware
	AuthController    *controller.AuthController
}

func NewRouteApp(
	authJwtMiddleware *middleware.AuthJwtMiddleware,
	authController *controller.AuthController,
) *RouteApp {
	return &RouteApp{
		AuthJwtMiddleware: authJwtMiddleware,
		AuthController:    authController,
	}
}

func (c *RouteApp) SetupRoutes(app *fiber.App) {
	c.guestApiRoute(app)
	c.protectedApiRoute(app)
}

func (c *RouteApp) guestApiRoute(app *fiber.App) {
	api := app.Group("/api/v1")
	{
		api.Get("/refresh-token", c.AuthJwtMiddleware.ValidateRefreshToken, c.AuthController.VerifyRefreshToken)
		api.Post("/register", c.AuthController.Register)
		api.Post("/login", c.AuthController.Login)
	}
}

func (c *RouteApp) protectedApiRoute(app *fiber.App) {
	api := app.Group("/api/v1").Use(c.AuthJwtMiddleware.ValidateAccessToken)
	{
		api.Get("/profile", c.AuthController.Profile)
		api.Get("/photo-profile", c.AuthController.GetPhotoProfile)
		api.Get("/my-login", c.AuthController.FindLoginUserByUserId)
		api.Patch("/update-password", c.AuthController.UpdatePassword)
		api.Patch("/upload-photo-profile", c.AuthController.UploadPhotoProfile)
		api.Delete("/force-logout", c.AuthController.ForceLogout)
		api.Delete("/logout", c.AuthController.Logout)
	}
}

// func apiGroup(app *fiber.App, prefix string) fiber.Router {
// 	return app.Group(prefix)
// }
