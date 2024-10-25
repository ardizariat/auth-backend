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

// func (m *MockAuthService) Register(ctx context.Context, req model.RegisterRequest) (*model.RegisterResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*model.RegisterResponse), args.Error(1)
// }
