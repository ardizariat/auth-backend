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

// func UserToTokenResponse(user *entity.User) *model.UserResponse {
// 	return &model.UserResponse{
// 		Token: user.CredentialID,
// 	}
// }
