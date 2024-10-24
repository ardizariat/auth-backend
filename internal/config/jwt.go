package config

import (
	"arch/pkg/appjwt"

	"github.com/spf13/viper"
)

func NewJwtWrapper(config *viper.Viper) *appjwt.JwtWrapper {
	return &appjwt.JwtWrapper{
		SecretKeyAccessToken:   config.GetString("jwt.secret_key_access_token"),
		SecretKeyRefreshToken:  config.GetString("jwt.secret_key_refresh_token"),
		Issuer:                 config.GetString("jwt.issuer"),
		ExpirationAccessToken:  config.GetInt64("jwt.exipiration_hours_access_token"),
		ExpirationRefreshToken: config.GetInt64("jwt.exipiration_day_refresh_token"),
	}
}
