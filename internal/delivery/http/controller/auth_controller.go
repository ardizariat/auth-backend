package controller

import (
	"arch/internal/helper/constants"
	"arch/internal/model"
	"arch/internal/usecase"
	"arch/pkg/apperror"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type AuthController struct {
	Validator   *validator.Validate
	Logger      *logrus.Logger
	AuthUseCase *usecase.AuthUseCase
}

func NewAuthController(
	validator *validator.Validate,
	logger *logrus.Logger,
	authUseCase *usecase.AuthUseCase,
) *AuthController {
	return &AuthController{
		Validator:   validator,
		Logger:      logger,
		AuthUseCase: authUseCase,
	}
}

func (c *AuthController) Register(ctx *fiber.Ctx) error {
	request := new(model.RegisterUserRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Logger, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Logger, err)
	}

	request.UserAgent = ctx.Get("User-Agent")
	request.IpAddress = ctx.IP()

	response, err := c.AuthUseCase.Register(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Logger, err)
	}

	return ctx.
		Status(http.StatusCreated).
		JSON(model.WebResponse[*model.UserRegisterResponse]{
			Data:    response,
			Message: "register successfully",
		})
}

func (c *AuthController) Login(ctx *fiber.Ctx) error {
	request := new(model.LoginUserRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Logger, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Logger, err)
	}

	request.UserAgent = ctx.Get("User-Agent")
	request.IpAddress = ctx.IP()

	response, err := c.AuthUseCase.Login(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Logger, err)
	}

	return ctx.JSON(model.WebResponse[*model.UserLoginResponse]{Data: response})
}

func (c *AuthController) Profile(ctx *fiber.Ctx) error {
	authJwt, ok := ctx.Locals(constants.AUTH_JWT).(*model.UserProfileResponse)
	if !ok || authJwt == nil {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[*model.UserProfileResponse]{
			Message: http.StatusText(http.StatusUnauthorized),
		})
	}
	return ctx.JSON(model.WebResponse[*model.UserProfileResponse]{Data: authJwt})
}

func (m *AuthController) VerifyRefreshToken(ctx *fiber.Ctx) error {
	refreshToken, ok := ctx.Locals(constants.REFRESH_TOKEN).(string)
	if !ok || refreshToken == "" {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[string]{
			Message: http.StatusText(http.StatusUnauthorized),
		})
	}
	response, err := m.AuthUseCase.VerifyRefreshToken(ctx.UserContext(), refreshToken)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}
	return ctx.
		JSON(model.WebResponse[string]{
			Data:    response,
			Message: "refresh token successfully",
		})
}

func (c *AuthController) UpdatePassword(ctx *fiber.Ctx) error {
	authJwt, ok := ctx.Locals(constants.AUTH_JWT).(*model.UserProfileResponse)
	if !ok || authJwt == nil {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[*model.UserProfileResponse]{
			Message: http.StatusText(http.StatusUnauthorized),
		})
	}
	request := new(model.UpdatePasswordLoginRequest)
	request.ID = authJwt.UserID
	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Logger, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Logger, err)
	}

	if err := c.AuthUseCase.UpdatePassword(ctx.UserContext(), request); err != nil {
		return apperror.HandleError(ctx, c.Logger, err)
	}

	return ctx.JSON(model.WebResponse[*model.UserProfileResponse]{Message: "update password successfully"})
}

func (c *AuthController) Logout(ctx *fiber.Ctx) error {
	authJwt, ok := ctx.Locals(constants.AUTH_JWT).(*model.UserProfileResponse)
	if !ok || authJwt == nil {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[*model.UserProfileResponse]{
			Message: http.StatusText(http.StatusUnauthorized),
		})
	}

	if err := c.AuthUseCase.Logout(ctx.UserContext(), authJwt); err != nil {
		return apperror.HandleError(ctx, c.Logger, err)
	}

	ctx.Locals(constants.AUTH_JWT, nil)

	return ctx.JSON(model.WebResponse[*model.UserProfileResponse]{Message: "logout successfully"})
}
