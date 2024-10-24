package model

import (
	"github.com/golang-jwt/jwt/v5"
)

type JwtClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}
