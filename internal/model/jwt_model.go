package model

import (
	"github.com/golang-jwt/jwt/v5"
)

type JwtClaims struct {
	ID            string `json:"id,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	Name          string `json:"name,omitempty"`
	Username      string `json:"username,omitempty"`
	Email         string `json:"email,omitempty"`
	PersonalEmail string `json:"personal_email,omitempty"`
	NIP           string `json:"nip,omitempty"`
	Token         string `json:"token,omitempty"`
	jwt.RegisteredClaims
}

type UserProfileResponse struct {
	ID            string `json:"id,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	Name          string `json:"name,omitempty"`
	Username      string `json:"username,omitempty"`
	Email         string `json:"email,omitempty"`
	PersonalEmail string `json:"personal_email,omitempty"`
	NIP           string `json:"nip,omitempty"`
	Token         string `json:"token,omitempty"`
}
