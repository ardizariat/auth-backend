package config

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewDatabase(viper *viper.Viper, log *logrus.Logger) *gorm.DB {
	connection := viper.GetString("database.connection")
	switch connection {
	case "postgres":
		return newDatabasePostgresConnection(viper, log)
	default:
		return nil
	}
}

func newDatabasePostgresConnection(viper *viper.Viper, log *logrus.Logger) *gorm.DB {
	username := viper.GetString("database.username")
	password := viper.GetString("database.password")
	host := viper.GetString("database.host")
	port := viper.GetInt("database.port")
	database := viper.GetString("database.name")
	timezone := viper.GetString("database.timezone")
	idleConnection := viper.GetInt("database.idle_connection")
	maxConnection := viper.GetInt("database.max_connection")
	maxLifeTimeConnection := viper.GetInt("database.max_life_time_connection")

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=%s",
		host, username, password, database, port, timezone,
	)

	psql, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.New(&LogrusWriter{Logger: log}, logger.Config{
			SlowThreshold:             time.Second * 5,
			Colorful:                  false,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			LogLevel:                  logger.Warn,
		}),
	})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	connection, err := psql.DB()
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
	connection.SetMaxIdleConns(idleConnection)
	connection.SetMaxOpenConns(maxConnection)
	connection.SetConnMaxLifetime(time.Second * time.Duration(maxLifeTimeConnection))
	return psql
}
