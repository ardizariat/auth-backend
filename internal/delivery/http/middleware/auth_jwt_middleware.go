package middleware

import (
	"arch/internal/model"
	"arch/internal/usecase"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

type AuthJwtMiddleware struct {
	UseCase *usecase.AuthUseCase
}

func NewAuthJwtMiddleware(userUseCase *usecase.AuthUseCase) *AuthJwtMiddleware {
	return &AuthJwtMiddleware{
		UseCase: userUseCase,
	}
}

func (m *AuthJwtMiddleware) ValidateAccessToken(ctx *fiber.Ctx) error {
	header := ctx.Get("Authorization")

	if header == "" {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}

	tokenEncrypt := parts[1]
	claims, err := m.UseCase.VerifyAccessToken(ctx.UserContext(), tokenEncrypt)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}
	ctx.Locals("authJwt", claims)
	return ctx.Next()
}

func (m *AuthJwtMiddleware) ValidateRefreshToken(ctx *fiber.Ctx) error {
	header := ctx.Get("Authorization")

	if header == "" {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 || parts[0] != "Refresh" {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}

	tokenEncrypt := parts[1]
	claims, err := m.UseCase.VerifyAccessToken(ctx.UserContext(), tokenEncrypt)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}
	ctx.Locals("authJwt", claims)
	return ctx.Next()
}
