package config

import (
	"arch/internal/model"
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/spf13/viper"
)

func NewRabbitMQ(config *viper.Viper) *model.RabbitMQClient {
	host := config.GetString("rabbitmq.url")
	rabbitMQ, err := amqp.Dial(host)
	if err != nil {
		panic(fmt.Errorf("fatal error connect host: %w", err))
	}

	channel, err := rabbitMQ.Channel()
	if err != nil {
		panic(fmt.Errorf("fatal error connect channel: %w", err))
	}

	return &model.RabbitMQClient{
		Connection: rabbitMQ,
		Channel:    channel,
	}
}
