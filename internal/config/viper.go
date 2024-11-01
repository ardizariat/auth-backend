package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

func NewViper() *viper.Viper {
	config := viper.New()
	config.SetConfigName("config")
	config.SetConfigType("yaml")

	rootDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	// Add the root directory and other relative paths
	config.AddConfigPath(rootDir)    // Root directory
	config.AddConfigPath("./")       // Current directory
	config.AddConfigPath("./../")    // One level up
	config.AddConfigPath("./../../") // Two levels up (for tests run in deeper directories)

	err = config.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	return config
}
