package model

import (
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/sirupsen/logrus"
)

type RabbitMQClient struct {
	Connection *amqp.Connection
	Channel    *amqp.Channel
	Log        *logrus.Logger
}
