package config

import (
	"fmt"

	"github.com/spf13/viper"
)

func NewViper() *viper.Viper {
	config := viper.New()
	config.SetConfigName("config")        // name of config file (without extension)
	config.SetConfigType("yaml")          // REQUIRED if the config file does not have the extension in the name
	config.AddConfigPath("/etc/appname/") // path to look for the config file in
	config.AddConfigPath(".")             // optionally look for config in the working directory
	err := config.ReadInConfig()          // Find and read the config file
	if err != nil {                       // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	return config
}
