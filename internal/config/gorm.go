package config

import (
	"arch/internal/model"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ProvideOauthDatabase initializes the Oauth database connection
func ProvideAuthDatabase(viper *viper.Viper, log *logrus.Logger) model.AuthDatabase {
	return newDatabaseConnection("database.oauth", viper, log)
}

// ProvideIthubDatabase initializes the ITHub database connection
func ProvideIthubDatabase(viper *viper.Viper, log *logrus.Logger) model.IthubDatabase {
	return newDatabaseConnection("database.ithub", viper, log)
}

// Generic function to establish a new database connection
func newDatabaseConnection(prefix string, viper *viper.Viper, log *logrus.Logger) *gorm.DB {
	user := viper.GetString(fmt.Sprintf("%s.user", prefix))
	password := viper.GetString(fmt.Sprintf("%s.password", prefix))
	host := viper.GetString(fmt.Sprintf("%s.host", prefix))
	port := viper.GetInt(fmt.Sprintf("%s.port", prefix))
	database := viper.GetString(fmt.Sprintf("%s.name", prefix))
	timezone := viper.GetString(fmt.Sprintf("%s.timezone", prefix))
	idleConnection := viper.GetInt(fmt.Sprintf("%s.idle_connection", prefix))
	maxConnection := viper.GetInt(fmt.Sprintf("%s.max_connection", prefix))
	maxLifeTimeConnection := viper.GetInt(fmt.Sprintf("%s.max_life_time_connection", prefix))

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=%s",
		host, user, password, database, port, timezone,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.New(&LogrusWriter{Logger: log}, logger.Config{
			SlowThreshold:             time.Second * 5,
			Colorful:                  false,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			LogLevel:                  logger.Warn,
		}),
	})
	if err != nil {
		log.Errorf("Failed to connect to database (%s): %v", prefix, err)
		return nil
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Errorf("Failed to configure database connection pooling (%s): %v", prefix, err)
		return nil
	}
	sqlDB.SetMaxIdleConns(idleConnection)
	sqlDB.SetMaxOpenConns(maxConnection)
	sqlDB.SetConnMaxLifetime(time.Second * time.Duration(maxLifeTimeConnection))

	return db
}
