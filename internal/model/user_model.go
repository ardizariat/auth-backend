package model

import (
	"mime/multipart"
	"time"
)

type UserResponse struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Username      string `json:"username,omitempty"`
	Email         string `json:"email,omitempty"`
	PersonalEmail string `json:"personal_email,omitempty" gorm:"column:personal_email"`
	NIP           string `json:"nip,omitempty" gorm:"column:nip"`
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

type UpdatePasswordLoginRequest struct {
	ID          string `json:"id" validate:"required"`
	OldPassword string `json:"old_password" validate:"required"`
	Password    string `json:"password" validate:"required,min=3"`
}

type LoginUserQueryResponse struct {
	ID            string  `json:"id,omitempty"`
	UserID        string  `json:"user_id,omitempty"`
	Name          string  `json:"name,omitempty"`
	Username      string  `json:"username,omitempty"`
	Email         string  `json:"email,omitempty"`
	PersonalEmail *string `json:"personal_email,omitempty"`
}

type LoginUserByPersonalEmail struct {
	ID            string  `json:"id,omitempty"`
	Name          string  `json:"name,omitempty"`
	Username      string  `json:"username,omitempty"`
	Email         string  `json:"email,omitempty"`
	PersonalEmail *string `json:"personal_email,omitempty"`
}

type LoginUserResponse struct {
	ID            string    `json:"id,omitempty"`
	UserID        string    `json:"user_id,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	IpAddress     string    `json:"ip_address,omitempty"`
	FirebaseToken *string   `json:"firebase_token,omitempty"`
	Model         *string   `json:"model,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

type LoginUserRequest struct {
	User          string  `json:"user" validate:"required,min=3"`
	Password      string  `json:"password" validate:"required,min=3"`
	UserAgent     string  `json:"user_agent"`
	IpAddress     string  `json:"ip_address"`
	FirebaseToken *string `json:"firebase_token"`
	Model         *string `json:"model"`
}

type ValidateOTPRequest struct {
	OTP    string `json:"otp" validate:"required,min=3"`
	UserID string `json:"user_id"`
}

type LoginUserByPersonalEmailRequest struct {
	PersonalEmail string  `json:"personal_email" validate:"required"`
	UserAgent     string  `json:"user_agent"`
	IpAddress     string  `json:"ip_address"`
	FirebaseToken *string `json:"firebase_token"`
	Model         *string `json:"model"`
}

type RegisterUserRequest struct {
	Name          string  `json:"name" validate:"required,min=1"`
	Username      string  `json:"username" validate:"required,min=3"`
	Email         string  `json:"email" validate:"required,min=3,email"`
	Password      string  `json:"password" validate:"required,min=3"`
	UserAgent     string  `json:"user_agent"`
	IpAddress     string  `json:"ip_address"`
	FirebaseToken *string `json:"firebase_token"`
	Model         *string `json:"model"`
	Pin           *uint16 `json:"pin"`
}

type ForceLogoutRequest struct {
	IDs []string `json:"ids" validate:"required,min=1"`
}

type UploadPhotoProfile struct {
	ID    string                  `json:"id"`
	Files []*multipart.FileHeader `json:"files"`
}

type AwsS3UploadMessage struct {
	FileBuffer []byte `json:"file_buffer"`
	Directory  string `json:"directory"`
}

type DataFirebaseToken struct {
	FirebaseToken string `json:"firebase_token"`
	Name          string `json:"name"`
}

type RequestFirebaseToken struct {
	UserIds []string `json:"user_ids" validate:"required,dive,required"`
}
