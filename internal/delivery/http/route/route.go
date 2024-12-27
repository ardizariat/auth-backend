package route

import (
	"arch/internal/delivery/http/controller"
	"arch/internal/delivery/http/middleware"

	"github.com/gofiber/fiber/v2"
)

type RouteApp struct {
	AuthJwtMiddleware *middleware.AuthJwtMiddleware
	AuthController    *controller.AuthController
	ClientController  *controller.ClientController
}

func NewRouteApp(
	authJwtMiddleware *middleware.AuthJwtMiddleware,
	authController *controller.AuthController,
	clientController *controller.ClientController,
) *RouteApp {
	return &RouteApp{
		AuthJwtMiddleware: authJwtMiddleware,
		AuthController:    authController,
		ClientController:  clientController,
	}
}

func (c *RouteApp) SetupRoutes(app *fiber.App) {
	c.guestApiRoute(app)
	c.protectedApiRoute(app)
}

func (c *RouteApp) guestApiRoute(app *fiber.App) {
	api := app.Group("/api/v1")
	api.Post("/register", c.AuthController.Register)
	api.Post("/login", c.AuthController.Login)
	api.Post("/login/oauth", c.AuthController.LoginByPersonalEmailOAuth)

	/* Client */
	client := api.Group("/clients")
	client.Get("/verify", c.ClientController.VerifyKey)
	client.Get("/google/oauth", c.ClientController.GoogleOAuthLogin)
	client.Get("/google/oauth/callback", c.ClientController.GoogleOAuthCallback)
	client.Post("/login", c.ClientController.ClientLogin)
	client.Post("/login-with-otp", c.ClientController.ClientLoginWithOtp)

	api.Get("/refresh-token", c.AuthJwtMiddleware.ValidateRefreshToken, c.AuthController.VerifyRefreshToken)
}

func (c *RouteApp) protectedApiRoute(app *fiber.App) {
	api := app.Group("/api/v1")
	api.Use(c.AuthJwtMiddleware.ValidateAccessToken)
	api.Get("/profile", c.AuthController.Profile)
	api.Get("/photo-profile", c.AuthController.GetPhotoProfile)
	api.Get("/my-login", c.AuthController.FindLoginUserByUserId)
	api.Post("/generate-otp", c.AuthController.GenerateOtp)
	api.Post("/validate-otp", c.AuthController.ValidateOTP)
	api.Patch("/update-password", c.AuthController.UpdatePassword)
	api.Patch("/upload-photo-profile", c.AuthController.UploadPhotoProfile)
	api.Delete("/force-logout", c.AuthController.ForceLogout)
	api.Delete("/logout", c.AuthController.Logout)

	user := api.Group("/users")
	user.Post("/firebase-token", c.AuthController.GetAllFirebaseTokenByUserIds)

	/* Client */
	client := api.Group("/clients")
	client.Get("/", c.ClientController.Index)
	client.Post("/", c.ClientController.Create)
}

// func apiGroup(app *fiber.App, prefix string) fiber.Router {
// 	return app.Group(prefix)
// }
