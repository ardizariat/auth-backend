package usecase

import (
	"arch/internal/model"
	"context"

	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(ctx context.Context, request *model.LoginUserRequest) (*model.UserLoginResponse, error) {
	args := m.Called(ctx, request)

	// Check if the first argument (UserLoginResponse) is nil before casting
	var response *model.UserLoginResponse
	if args.Get(0) != nil {
		response = args.Get(0).(*model.UserLoginResponse)
	}

	return response, args.Error(1)
}

func (m *MockAuthService) Register(ctx context.Context, request *model.RegisterUserRequest) (*model.UserRegisterResponse, error) {
	args := m.Called(ctx, request)

	var response *model.UserRegisterResponse
	if args.Get(0) != nil {
		response = args.Get(0).(*model.UserRegisterResponse)
	}

	return response, args.Error(1)
}
func (m *MockAuthService) GetCurrentProfile(ctx context.Context, token string) (*model.UserProfileResponse, error) {
	args := m.Called(ctx, token)
	if user, ok := args.Get(0).(*model.UserProfileResponse); ok {
		return user, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	if newToken, ok := args.Get(0).(string); ok {
		return newToken, args.Error(1)
	}
	return "", args.Error(1)
}
