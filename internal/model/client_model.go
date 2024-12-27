package model

type ClientRequest struct {
	Name        string  `json:"name" validate:"required,min=1"`
	BaseURL     string  `json:"base_url" validate:"required,min=5"`
	CallbackURL string  `json:"callback_url" validate:"required,min=5"`
	Enabled     bool    `json:"enabled"`
	Description *string `json:"description"`
}

type ClientLoginUserRequest struct {
	ClientName    string  `json:"client_name" validate:"required"`
	User          string  `json:"user" validate:"required,min=3"`
	Password      string  `json:"password" validate:"required,min=3"`
	UserAgent     string  `json:"user_agent"`
	IpAddress     string  `json:"ip_address"`
	FirebaseToken *string `json:"firebase_token"`
	Model         *string `json:"model"`
}

type ClientUserLoginResponse struct {
	Token       string `json:"token"`
	CallbackURL string `json:"callback_url"`
}

type ClientVerifyKeyRequest struct {
	Key string `json:"key" validate:"required"`
}

type ClientLoginUserOTPRequest struct {
	ClientName    string  `json:"client_name" validate:"required"`
	OTP           string  `json:"otp" validate:"required,min=5"`
	Username      string  `json:"username" validate:"required"`
	UserAgent     string  `json:"user_agent"`
	IpAddress     string  `json:"ip_address"`
	FirebaseToken *string `json:"firebase_token"`
	Model         *string `json:"model"`
}

type ClientGoogleOauthUserInfo struct {
	Email         string `json:"email"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	VerifiedEmail bool   `json:"verified_email"`
}
