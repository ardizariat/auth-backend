package controller

import (
	"arch/internal/usecase"

	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
)

type UserController struct {
	Validator   *validator.Validate
	Log         *logrus.Logger
	UserUseCase *usecase.UserUseCase
}

func NewUserController(validator *validator.Validate, log *logrus.Logger, userUseCase *usecase.UserUseCase) *UserController {
	return &UserController{
		Validator:   validator,
		Log:         log,
		UserUseCase: userUseCase,
	}
}
