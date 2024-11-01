package model

import amqp "github.com/rabbitmq/amqp091-go"

type RabbitMQClient struct {
	Connection *amqp.Connection
	Channel    *amqp.Channel
}
