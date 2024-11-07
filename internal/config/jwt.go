package config

import (
	"arch/pkg/appjwt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func NewJwtWrapper(config *viper.Viper, log *logrus.Logger) *appjwt.JwtWrapper {
	// Parse the durations using time.ParseDuration
	expirationAccessToken, err := time.ParseDuration(config.GetString("jwt.expiration_access_token"))
	if err != nil {
		log.Fatalf("failed to parse access token expiration: %v", err)
	}

	expirationRefreshToken, err := time.ParseDuration(config.GetString("jwt.expiration_refresh_token"))
	if err != nil {
		log.Fatalf("failed to parse refresh token expiration: %v", err)
	}
	return &appjwt.JwtWrapper{
		SecretKeyAccessToken:   config.GetString("jwt.secret_key_access_token"),
		SecretKeyRefreshToken:  config.GetString("jwt.secret_key_refresh_token"),
		Issuer:                 config.GetString("jwt.issuer"),
		ExpirationAccessToken:  expirationAccessToken,
		ExpirationRefreshToken: expirationRefreshToken,
	}
}
