package service_test

import (
	"arch/internal/model"
	"arch/internal/usecase"
	"arch/pkg/apperror"
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLogin(t *testing.T) {
	mockAuthService := new(usecase.MockAuthService)

	t.Run("login success", func(t *testing.T) {
		req := &model.LoginUserRequest{
			User:     "admin",
			Password: "111",
		}

		resp := &model.UserLoginResponse{
			User: model.UserResponse{
				ID:       "0192bdf3-c223-78a5-88ff-58801a161914",
				Name:     "admin",
				Username: "admin",
				Email:    "admin@mail.com",
			},
			Token: model.TokenResponse{
				AccessToken:  "1",
				RefreshToken: "2",
			},
		}

		// Mock the behavior of AuthService.Login
		mockAuthService.On("Login", mock.Anything, req).Return(resp, nil)
		result, err := mockAuthService.Login(context.TODO(), req)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "1", result.Token.AccessToken)
		assert.Equal(t, "2", result.Token.RefreshToken)
		assert.Equal(t, "0192bdf3-c223-78a5-88ff-58801a161914", result.User.ID)
		assert.Equal(t, "admin", result.User.Name)
		assert.Equal(t, "admin", result.User.Username)
		assert.Equal(t, "admin@mail.com", result.User.Email)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("login fail", func(t *testing.T) {
		req := &model.LoginUserRequest{
			User:     "user@example.com",
			Password: "password123",
		}

		// Mock the behavior to return an error (use an appropriate error type)
		mockAuthService.On("Login", mock.Anything, req).Return(nil, apperror.NewAppError(http.StatusUnauthorized))

		result, err := mockAuthService.Login(context.TODO(), req)

		assert.Nil(t, result)
		assert.Error(t, err)
		var appErr *apperror.Error
		if errors.As(err, &appErr) {
			assert.Equal(t, http.StatusUnauthorized, appErr.Code)
		} else {
			t.Errorf("expected *apperror.AppError, got %T", err)
		}
		mockAuthService.AssertExpectations(t)

	})
}

func TestRegister(t *testing.T) {
	mockAuthService := new(usecase.MockAuthService)
	t.Run("register success", func(t *testing.T) {
		req := &model.RegisterUserRequest{
			Name:     "jhon",
			Username: "jhon",
			Email:    "jhon@mail.com",
			Password: "111",
		}

		resp := &model.UserRegisterResponse{
			User: model.UserResponse{
				ID:       "2",
				Name:     "jhon",
				Username: "jhon",
				Email:    "jhon@mail.com",
			},
			Token: model.TokenResponse{
				AccessToken:  "1",
				RefreshToken: "2",
			},
		}

		mockAuthService.On("Register", mock.Anything, req).Return(resp, nil)

		result, err := mockAuthService.Register(context.TODO(), req)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "1", result.Token.AccessToken)
		assert.Equal(t, "2", result.Token.RefreshToken)
		assert.Equal(t, "2", result.User.ID)
		assert.Equal(t, "jhon", result.User.Name)
		assert.Equal(t, "jhon", result.User.Username)
		assert.Equal(t, "jhon@mail.com", result.User.Email)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("register fail username exists", func(t *testing.T) {
		req := &model.RegisterUserRequest{
			Name:     "existinguser",
			Username: "jhexistinguseron",
			Email:    "existinguser@mail.com",
			Password: "111",
		}

		mockAuthService.On("Register", mock.Anything, req).Return(nil, apperror.NewAppError(http.StatusConflict, fmt.Sprintf("username %s sudah terdaftar", req.Username)))

		result, err := mockAuthService.Register(context.TODO(), req)
		assert.Nil(t, result)
		assert.Error(t, err)
		var appErr *apperror.Error
		if errors.As(err, &appErr) {
			assert.Equal(t, http.StatusConflict, appErr.Code)
			assert.Equal(t, fmt.Sprintf("username %s sudah terdaftar", req.Username), appErr.Message)
		} else {
			t.Errorf("expected *apperror.AppError, got %T", err)
		}

		mockAuthService.AssertExpectations(t)
	})

	t.Run("register fail email exists", func(t *testing.T) {
		mockAuthService := new(usecase.MockAuthService)
		req := &model.RegisterUserRequest{
			Name:     "existinguser",
			Username: "jhexistinguseron",
			Email:    "existinguser@mail.com",
			Password: "111",
		}

		mockAuthService.On("Register", mock.Anything, req).Return(nil, apperror.NewAppError(http.StatusConflict, fmt.Sprintf("email %s sudah terdaftar", req.Email)))

		result, err := mockAuthService.Register(context.TODO(), req)
		assert.Nil(t, result)
		assert.Error(t, err)
		var appErr *apperror.Error
		if errors.As(err, &appErr) {
			assert.Equal(t, http.StatusConflict, appErr.Code)
			assert.Equal(t, fmt.Sprintf("email %s sudah terdaftar", req.Email), appErr.Message)
		} else {
			t.Errorf("expected *apperror.AppError, got %T", err)
		}

		mockAuthService.AssertExpectations(t)
	})
}
