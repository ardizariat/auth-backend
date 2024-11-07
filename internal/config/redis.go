package config

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func NewRedis(config *viper.Viper, log *logrus.Logger) *redis.Client {
	host := config.GetString("redis.host")
	port := config.GetInt("redis.port")
	password := config.GetString("redis.password")
	db := config.GetInt("redis.db")
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password,
		DB:       db,
	})

	// Ping the Redis server
	ctx := context.Background()
	_, err := client.Ping(ctx).Result()

	if err != nil {
		log.Fatalf("fatal error connect: %v", err)
	}
	return client
}
