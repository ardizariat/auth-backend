package converter

import (
	"arch/internal/entity"
	"arch/internal/model"
)

func UserToResponse(user *entity.User) *model.UserResponse {
	return &model.UserResponse{
		ID:   user.ID,
		Name: user.Name,
	}
}

func LoginUserToResponse(loginUser *entity.LoginUser) *model.LoginUserResponse {
	return &model.LoginUserResponse{
		ID:            loginUser.ID,
		UserID:        loginUser.UserID,
		IpAddress:     loginUser.IpAddress,
		Model:         loginUser.Model,
		FirebaseToken: loginUser.FirebaseToken,
		CreatedAt:     loginUser.CreatedAt,
	}
}
