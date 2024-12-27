package controller

import (
	"arch/internal/entity"
	"arch/internal/helper"
	"arch/internal/model"
	"arch/internal/usecase"
	"arch/pkg/apperror"
	"errors"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type ClientController struct {
	Validator     *validator.Validate
	Log           *logrus.Logger
	ClientUseCase *usecase.ClientUseCase
}

func NewClientController(
	validator *validator.Validate,
	log *logrus.Logger,
	clientUseCase *usecase.ClientUseCase,
) *ClientController {
	return &ClientController{
		Validator:     validator,
		Log:           log,
		ClientUseCase: clientUseCase,
	}
}

func (c *ClientController) Index(ctx *fiber.Ctx) error {
	result, err := c.ClientUseCase.GetAll(ctx.UserContext())
	if err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[[]entity.Client]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *ClientController) Create(ctx *fiber.Ctx) error {
	request := new(model.ClientRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	result, err := c.ClientUseCase.Create(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*entity.Client]{
		Data:       result,
		StatusCode: http.StatusCreated,
		Message:    "create successfully",
	})

	return ctx.Status(http.StatusCreated).JSON(res)
}

func (c *ClientController) ClientLogin(ctx *fiber.Ctx) error {
	request := new(model.ClientLoginUserRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	request.UserAgent = ctx.Get("User-Agent")
	request.IpAddress = ctx.IP()

	result, err := c.ClientUseCase.ClientLogin(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*model.ClientUserLoginResponse]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *ClientController) VerifyKey(ctx *fiber.Ctx) error {
	request := new(model.ClientVerifyKeyRequest)
	key := ctx.Query("key")
	if key == "" {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, "key is required"))
	}
	request.Key = key
	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	result, err := c.ClientUseCase.VerifyKey(ctx.UserContext(), key)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*model.UserLoginResponse]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *ClientController) ClientLoginWithOtp(ctx *fiber.Ctx) error {
	request := new(model.ClientLoginUserOTPRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	request.UserAgent = ctx.Get("User-Agent")
	request.IpAddress = ctx.IP()

	result, err := c.ClientUseCase.ClientLoginWithOtp(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*model.ClientUserLoginResponse]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *ClientController) GoogleOAuthLogin(ctx *fiber.Ctx) error {
	clientName := ctx.Query("client_name")
	if clientName == "" {
		return apperror.HandleError(ctx, c.Log, errors.New("client name is empty"))
	}
	result, err := c.ClientUseCase.GoogleOAuthLogin(ctx.UserContext(), clientName)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	return ctx.Redirect(result, http.StatusTemporaryRedirect)
}

func (c *ClientController) GoogleOAuthCallback(ctx *fiber.Ctx) error {
	state := ctx.Query("state")
	if state == "" {
		return apperror.HandleError(ctx, c.Log, errors.New("state is empty"))
	}
	code := ctx.Query("code")
	if code == "" {
		return apperror.HandleError(ctx, c.Log, errors.New("code is empty"))
	}
	result, err := c.ClientUseCase.GoogleOAuthCallback(ctx.UserContext(), state, code)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	c.Log.Info(result)
	return ctx.Redirect(result.CallbackURL, http.StatusTemporaryRedirect)
}
