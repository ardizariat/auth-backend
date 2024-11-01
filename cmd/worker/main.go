package main

import (
	"arch/internal/config"
	"arch/internal/gateway/consumer"
	"os"
)

func main() {
	viperConfig := config.NewViper()
	connection := config.NewRabbitMQ(viperConfig)
	rabbitMQConsumer := consumer.NewRabbitMQConsumer(connection)

	routingKey := os.Args[1]
	if routingKey == "email" {
		rabbitMQConsumer.ConsumeMessage("notification", routingKey)
	} else if routingKey == "sms" {
		rabbitMQConsumer.ConsumeMessage("notification", routingKey)
	}
}
