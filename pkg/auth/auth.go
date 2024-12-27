package auth

import (
	"arch/internal/helper/constants"
	"arch/internal/model"

	"github.com/gofiber/fiber/v2"
)

func GetUser(ctx *fiber.Ctx) (*model.UserProfileResponse, bool) {
	authJwt, ok := ctx.Locals(constants.AUTH_JWT).(*model.UserProfileResponse)
	if !ok || authJwt == nil {
		return nil, false
	}
	return authJwt, true
}
