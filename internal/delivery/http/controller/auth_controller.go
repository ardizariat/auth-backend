package controller

import (
	"arch/internal/helper"
	"arch/internal/helper/constants"
	"arch/internal/model"
	"arch/internal/usecase"
	"arch/pkg/apperror"
	"arch/pkg/auth"
	"net/http"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type AuthController struct {
	Validator   *validator.Validate
	Log         *logrus.Logger
	AuthUseCase *usecase.AuthUseCase
}

func NewAuthController(
	validator *validator.Validate,
	log *logrus.Logger,
	authUseCase *usecase.AuthUseCase,
) *AuthController {
	return &AuthController{
		Validator:   validator,
		Log:         log,
		AuthUseCase: authUseCase,
	}
}

func (c *AuthController) Register(ctx *fiber.Ctx) error {
	request := new(model.RegisterUserRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	request.UserAgent = ctx.Get("User-Agent")
	request.IpAddress = ctx.IP()

	result, err := c.AuthUseCase.Register(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*model.UserRegisterResponse]{
		Data:       result,
		StatusCode: http.StatusCreated,
		Message:    "create successfully",
	})
	return ctx.Status(http.StatusCreated).JSON(res)
}

func (c *AuthController) Login(ctx *fiber.Ctx) error {
	request := new(model.LoginUserRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	request.UserAgent = ctx.Get("User-Agent")
	request.IpAddress = ctx.IP()

	result, err := c.AuthUseCase.Login(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*model.UserLoginResponse]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *AuthController) LoginByPersonalEmailOAuth(ctx *fiber.Ctx) error {
	request := new(model.LoginUserByPersonalEmailRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	request.UserAgent = ctx.Get("User-Agent")
	request.IpAddress = ctx.IP()

	result, err := c.AuthUseCase.GetUserByPersonalEmail(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*model.UserLoginResponse]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *AuthController) Profile(ctx *fiber.Ctx) error {
	auth, ok := auth.GetUser(ctx)
	if !ok {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusUnauthorized))
	}
	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*model.UserProfileResponse]{
		Data: auth,
	})
	return ctx.JSON(res)
}

func (m *AuthController) VerifyRefreshToken(ctx *fiber.Ctx) error {
	refreshToken, ok := ctx.Locals(constants.REFRESH_TOKEN).(string)
	if !ok || refreshToken == "" {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[string]{
			Message: http.StatusText(http.StatusUnauthorized),
		})
	}
	result, err := m.AuthUseCase.VerifyRefreshToken(ctx.UserContext(), refreshToken)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(model.WebResponse[any]{Message: http.StatusText(http.StatusUnauthorized)})
	}
	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[string]{
		Message: "refresh token successfully",
		Data:    result,
	})
	return ctx.JSON(res)
}

func (c *AuthController) UpdatePassword(ctx *fiber.Ctx) error {
	authJwt, ok := auth.GetUser(ctx)
	if !ok {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusUnauthorized))
	}
	request := new(model.UpdatePasswordLoginRequest)
	request.ID = authJwt.UserID
	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	if err := c.AuthUseCase.UpdatePassword(ctx.UserContext(), request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[any]{
		Message: "update password successfully",
	})
	return ctx.JSON(res)
}

func (c *AuthController) Logout(ctx *fiber.Ctx) error {
	authJwt, ok := auth.GetUser(ctx)
	if !ok {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusUnauthorized))
	}

	if err := c.AuthUseCase.Logout(ctx.UserContext(), authJwt); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	ctx.Locals(constants.AUTH_JWT, nil)

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[any]{
		Message: "logout successfully",
	})
	return ctx.JSON(res)
}

func (c *AuthController) ForceLogout(ctx *fiber.Ctx) error {
	request := new(model.ForceLogoutRequest)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	if err := c.AuthUseCase.ForceLogout(ctx.UserContext(), request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[any]{
		Message: "force logout successfully",
	})
	return ctx.JSON(res)
}

func (c *AuthController) FindLoginUserByUserId(ctx *fiber.Ctx) error {
	authJwt, ok := auth.GetUser(ctx)
	if !ok {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusUnauthorized))
	}

	result, err := c.AuthUseCase.FindLoginUserByUserId(ctx.UserContext(), authJwt.UserID)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[[]model.LoginUserResponse]{
		Message: "get login user successfully",
		Data:    result,
	})
	return ctx.JSON(res)
}

func (c *AuthController) UploadPhotoProfile(ctx *fiber.Ctx) error {
	form, err := ctx.MultipartForm()
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	request := new(model.UploadPhotoProfile)

	// if err := c.Validator.Struct(request); err != nil {
	// 	return apperror.HandleError(ctx, c.Log, err)
	// }

	request.ID = helper.GetStringFromFormValue(form, "id")
	request.Files = form.File["files"]

	if err = c.AuthUseCase.UploadPhotoProfile(ctx.UserContext(), request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[any]{
		Message: "upload user successfully",
	})
	return ctx.JSON(res)
}

func (c *AuthController) GetPhotoProfile(ctx *fiber.Ctx) error {
	result, err := c.AuthUseCase.GetPhotoProfile(ctx.UserContext())
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[*v4.PresignedHTTPRequest]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *AuthController) GetAllFirebaseTokenByUserIds(ctx *fiber.Ctx) error {
	request := new(model.RequestFirebaseToken)

	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}
	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	result, err := c.AuthUseCase.GetAllFirebaseTokenByUserIds(ctx.UserContext(), request.UserIds)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}

	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[[]model.DataFirebaseToken]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *AuthController) GenerateOtp(ctx *fiber.Ctx) error {
	authJwt, ok := auth.GetUser(ctx)
	if !ok {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusUnauthorized))
	}
	result, err := c.AuthUseCase.GenerateOtp(ctx.UserContext(), authJwt)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[string]{
		Data: result,
	})
	return ctx.JSON(res)
}

func (c *AuthController) ValidateOTP(ctx *fiber.Ctx) error {
	authJwt, ok := auth.GetUser(ctx)
	if !ok {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusUnauthorized))
	}

	request := new(model.ValidateOTPRequest)
	request.UserID = authJwt.UserID
	if err := ctx.BodyParser(request); err != nil {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusBadRequest, err.Error()))
	}

	if err := c.Validator.Struct(request); err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	ok, err := c.AuthUseCase.ValidateOTP(ctx.UserContext(), request)
	if err != nil {
		return apperror.HandleError(ctx, c.Log, err)
	}
	if !ok {
		return apperror.HandleError(ctx, c.Log, apperror.NewAppError(http.StatusUnauthorized))
	}
	res := helper.ResponseSuccess(helper.HttpResponseParamSuccess[bool]{
		Data: ok,
	})
	return ctx.JSON(res)
}
