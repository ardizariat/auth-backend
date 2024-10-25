package model

type UserResponse struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type UserRegisterResponse struct {
	User  UserResponse  `json:"user,omitempty"`
	Token TokenResponse `json:"token,omitempty"`
}

type UserLoginResponse struct {
	User  UserResponse  `json:"user,omitempty"`
	Token TokenResponse `json:"token,omitempty"`
}

type UserProfileResponse struct {
	ID     string `json:"id,omitempty"`
	UserID string `json:"user_id,omitempty"`
	Name   string `json:"name,omitempty"`
	Email  string `json:"email,omitempty"`
	Token  string `json:"token,omitempty"`
}

type UpdatePasswordLoginRequest struct {
	ID          string `json:"id" validate:"required"`
	OldPassword string `json:"old_password" validate:"required"`
	Password    string `json:"password" validate:"required,min=3"`
}

type LoginUserQueryResponse struct {
	ID     string `json:"id,omitempty"`
	UserID string `json:"user_id,omitempty"`
	Name   string `json:"name,omitempty"`
	Email  string `json:"email,omitempty"`
}

type LoginUserRequest struct {
	User          string `json:"user" validate:"required,min=3"`
	Password      string `json:"password" validate:"required,min=3"`
	UserAgent     string `json:"user_agent"`
	IpAddress     string `json:"ip_address"`
	FirebaseToken string `json:"firebase_token"`
	Model         string `json:"model"`
}

type RegisterUserRequest struct {
	Name          string `json:"name" validate:"required,min=1"`
	Username      string `json:"username" validate:"required,min=3"`
	Email         string `json:"email" validate:"required,min=3,email"`
	Password      string `json:"password" validate:"required,min=3"`
	UserAgent     string `json:"user_agent"`
	IpAddress     string `json:"ip_address"`
	FirebaseToken string `json:"firebase_token"`
	Model         string `json:"model"`
}
