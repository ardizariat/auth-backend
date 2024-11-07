package config

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type LogrusWriter struct {
	Logger *logrus.Logger
}

func (l *LogrusWriter) Printf(message string, args ...interface{}) {
	l.Logger.Tracef(message, args...)
}

func NewLogrus(viperConfig *viper.Viper) *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.Level(viperConfig.GetInt32("app.log_level")))
	logger.SetFormatter(&logrus.JSONFormatter{})
	return logger
}
