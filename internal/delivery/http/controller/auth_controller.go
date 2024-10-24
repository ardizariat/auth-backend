package controller

import (
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
	response := ctx.Locals("authJwt").(*model.UserProfileResponse)
	return ctx.JSON(model.WebResponse[*model.UserProfileResponse]{Data: response})
}
