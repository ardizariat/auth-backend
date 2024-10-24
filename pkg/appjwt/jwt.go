package appjwt

import (
	"arch/internal/helper"
	"arch/internal/model"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtWrapper struct {
	SecretKeyAccessToken   string
	SecretKeyRefreshToken  string
	Issuer                 string
	ExpirationAccessToken  time.Duration
	ExpirationRefreshToken time.Duration
}

func (wrapper *JwtWrapper) GenerateToken(ID, secretKey string, expiration time.Duration) (string, error) {
	// expiresAt := time.Unix(time.Now().Add(expiration).Unix(), 0)
	expiresAt := time.Now().Add(expiration)

	claims := &model.JwtClaims{
		ID: ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    wrapper.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	encryptToken, err := helper.Encrypt(signedToken)
	if err != nil {
		return "", err
	}

	return encryptToken, nil
}

func (wrapper *JwtWrapper) GenerateAccessToken(loginUserID string) (string, error) {
	return wrapper.GenerateToken(loginUserID, wrapper.SecretKeyAccessToken, wrapper.ExpirationAccessToken)
}

func (wrapper *JwtWrapper) GenerateRefreshToken(loginUserID string) (string, error) {
	return wrapper.GenerateToken(loginUserID, wrapper.SecretKeyRefreshToken, wrapper.ExpirationRefreshToken)
}

func (wrapper *JwtWrapper) ValidateToken(signedToken, secretKey string) (*model.JwtClaims, error) {
	decryptToken, err := helper.Decrypt(signedToken)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(decryptToken, &model.JwtClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, errors.New("invalid signature key")
		}

		return nil, errors.New("token expired")
	}

	claims, ok := token.Claims.(*model.JwtClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	if claims.ExpiresAt.Unix() < time.Now().Unix() {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

// ValidateAccessToken validates the access token.
func (wrapper *JwtWrapper) ValidateAccessToken(signedToken string) (*model.JwtClaims, error) {
	return wrapper.ValidateToken(signedToken, wrapper.SecretKeyAccessToken)
}

// ValidateRefreshToken validates the refresh token.
func (wrapper *JwtWrapper) ValidateRefreshToken(signedToken string) (*model.JwtClaims, error) {
	return wrapper.ValidateToken(signedToken, wrapper.SecretKeyRefreshToken)
}
