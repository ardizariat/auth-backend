package apperror

import (
	"arch/internal/helper"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type ErrorValidation struct {
	Field          string `json:"field"`
	ValidationCode string `json:"validation_code"`
	Param          string `json:"param"`
	Message        string `json:"message"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error makes it compatible with the `error` interface.
func (e *Error) Error() string {
	return e.Message
}

func NewAppError(code int, message ...string) *Error {
	err := &Error{
		Code:    code,
		Message: http.StatusText(code),
	}
	if len(message) > 0 {
		err.Message = message[0]
	}
	return err
}

func HandleError(ctx *fiber.Ctx, log *logrus.Logger, err error) error {
	// If the error is a CustomError, return the custom status code and message
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		return ErrorBindingResponse(ctx, validationErrors)
	} else if customErr, ok := err.(*Error); ok {
		res := helper.ResponseError(helper.HttpResponseParamError[string]{
			Message:    customErr.Message,
			StatusCode: customErr.Code,
		})
		return ctx.Status(customErr.Code).JSON(res)
	}

	res := helper.ResponseError(helper.HttpResponseParamError[string]{
		Message:    err.Error(),
		StatusCode: http.StatusInternalServerError,
	})
	return ctx.Status(http.StatusInternalServerError).JSON(res)
}

func ErrorBindingResponse(ctx *fiber.Ctx, validationErrors validator.ValidationErrors) error {
	var responseErrors []ErrorValidation
	for _, fieldError := range validationErrors {
		field := fieldError.Field()
		responseErrors = append(responseErrors, ErrorValidation{
			Field:          strings.ToLower(field),
			ValidationCode: strings.ToUpper(fieldError.Tag()),
			Param:          fieldError.Param(),
			Message:        ParseFieldError(fieldError),
		})
	}
	res := helper.ResponseError(helper.HttpResponseParamError[[]ErrorValidation]{
		Message:    "validation error",
		StatusCode: http.StatusUnprocessableEntity,
		Errors:     responseErrors,
	})
	return ctx.Status(http.StatusUnprocessableEntity).JSON(res)
}

func ParseFieldError(e validator.FieldError) string {
	fieldPrefix := strings.ToLower(e.Field())
	tag := strings.Split(e.Tag(), "|")[0]
	switch tag {
	case "required":
		return fmt.Sprintf("%s wajib diisi", fieldPrefix)
	case "email":
		return fmt.Sprintf("%s harus berupa email", fieldPrefix)
	case "min":
		return fmt.Sprintf("%s minimal %s karakter", fieldPrefix, e.Param())
	case "gte":
		return fmt.Sprintf("%s harus lebih besar atau sama dengan %s", fieldPrefix, e.Param())
	case "let":
		return fmt.Sprintf("%s harus kurang dari atau sama dengan %s", fieldPrefix, e.Param())
	default:
		return fmt.Errorf("%v", e).Error()
	}
}
