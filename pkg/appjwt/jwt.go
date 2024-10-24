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
	ExpirationAccessToken  int64
	ExpirationRefreshToken int64
}

func (wrapper *JwtWrapper) GenerateToken(ID, secretKey string, expiration time.Duration) (string, error) {
	expiresAt := time.Unix(time.Now().Add(expiration*time.Hour).Unix(), 0)
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
		return nil, errors.New("unauthorized")
	}

	if claims.ExpiresAt.Unix() < time.Now().Unix() {
		return nil, errors.New("token is expired")
	}

	return claims, nil

	// if err != nil {
	// 	if err == jwt.ErrSignatureInvalid {
	// 		return nil, errors.New("invalid signature key")
	// 	}

	// 	return nil, errors.New("token expired")
	// }

	// claims, ok := token.Claims.(*model.JwtClaims)
	// if !ok {
	// 	return nil, errors.New("couldn't parse claims")
	// }

	// if claims.ExpiresAt.Unix() < time.Now().Unix() {
	// 	return nil, errors.New("token is expired")
	// }

	// return claims, nil
}

// GenerateAccessToken creates an access token with a specified expiration time.
func (wrapper *JwtWrapper) GenerateAccessToken(loginUserID string) (string, error) {
	return wrapper.GenerateToken(loginUserID, wrapper.SecretKeyAccessToken, time.Duration(wrapper.ExpirationAccessToken)*time.Hour)
}

// GenerateRefreshToken creates a refresh token with a specified expiration time.
func (wrapper *JwtWrapper) GenerateRefreshToken(credentialID string) (string, error) {
	return wrapper.GenerateToken(credentialID, wrapper.SecretKeyRefreshToken, time.Duration(wrapper.ExpirationAccessToken)*(time.Hour*24))
}

// ValidateAccessToken validates the access token.
func (wrapper *JwtWrapper) ValidateAccessToken(signedToken string) (*model.JwtClaims, error) {
	return wrapper.ValidateToken(signedToken, wrapper.SecretKeyAccessToken)
}

// ValidateRefreshToken validates the refresh token.
func (wrapper *JwtWrapper) ValidateRefreshToken(signedToken string) (*model.JwtClaims, error) {
	return wrapper.ValidateToken(signedToken, wrapper.SecretKeyRefreshToken)
}
