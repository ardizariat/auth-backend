package producer

import (
	"arch/internal/model"
	"context"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMQProducer struct {
	Connection *amqp.Connection
	Channel    *amqp.Channel
}

func NewRabbitMQProducer(rmq *model.RabbitMQClient) *RabbitMQProducer {
	return &RabbitMQProducer{
		Connection: rmq.Connection,
		Channel:    rmq.Channel,
	}
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func (r *RabbitMQProducer) PublishMessage(exchangeName, queueName string, message []byte) error {
	defer func() {
		r.Connection.Close()
		r.Channel.Close()
	}()

	// q, err := r.Channel.QueueDeclare(
	// 	"",    // name
	// 	false, // durable
	// 	false, // delete when unused
	// 	true,  // exclusive
	// 	false, // no-wait
	// 	nil,   // arguments
	// )
	// failOnError(err, "Failed to declare a queue")

	err := r.Channel.ExchangeDeclare(
		exchangeName,        // name
		amqp.ExchangeDirect, // durable
		true,                // delete when unused
		false,               // delete when unused
		false,               // exclusive
		false,               // no-wait
		nil,                 // arguments
	)
	failOnError(err, "Failed to declare a exchange")

	// err = r.Channel.QueueBind(
	// 	q.Name, // name
	// 	"",     // durable
	// 	"logs", // delete when unused
	// 	false,  // delete when unused
	// 	nil,    // arguments
	// )
	// failOnError(err, "Failed to declare a exchange")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := amqp.Publishing{
		ContentType: "text/plain",
		Body:        message,
	}
	err = r.Channel.PublishWithContext(
		ctx,
		exchangeName, // exchange
		queueName,    // routing key
		false,        // mandatory
		false,        // immediate
		payload,
	)
	failOnError(err, "Failed to publish a message")
	return nil
}
