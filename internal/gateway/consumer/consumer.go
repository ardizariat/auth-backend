package consumer

import (
	"arch/internal/model"
	"context"
	"fmt"
	"log"

	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMQConsumer struct {
	Connection *amqp.Connection
	Channel    *amqp.Channel
}

func NewRabbitMQConsumer(rmq *model.RabbitMQClient) *RabbitMQConsumer {
	return &RabbitMQConsumer{
		Connection: rmq.Connection,
		Channel:    rmq.Channel,
	}
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func (r *RabbitMQConsumer) ConsumeMessage(exchangeName, queueName string) {
	defer func() {
		r.Connection.Close()
		r.Channel.Close()
	}()

	q, err := r.Channel.QueueDeclare(
		queueName,                            // name
		true,                                 // durable
		false,                                // delete when unused
		false,                                // exclusive
		false,                                // no-wait
		amqp.Table{"x-queue-type": "quorum"}, // specify the queue type as "quorum"
	)
	failOnError(err, "Failed to declare a queue")

	err = r.Channel.ExchangeDeclare(
		exchangeName,        // name
		amqp.ExchangeDirect, // durable
		true,                // delete when unused
		false,               // delete when unused
		false,               // exclusive
		false,               // no-wait
		nil,                 // arguments
	)
	failOnError(err, "Failed to declare a exchange")

	err = r.Channel.QueueBind(
		q.Name,       // name
		q.Name,       // durable
		exchangeName, // delete when unused
		false,        // delete when unused
		nil,          // arguments
	)
	failOnError(err, "Failed to declare a exchange")

	ctx := context.Background()
	msgs, err := r.Channel.ConsumeWithContext(
		ctx,
		queueName,                             // queue
		fmt.Sprintf("consumer_%s", queueName), // consumer name
		true,                                  // auto ack
		false,                                 // exclusive
		false,                                 // no local
		false,                                 // no wait
		nil,                                   // args
	)
	failOnError(err, "Failed to register a consumer")

	var forever chan struct{}

	go func() {
		for d := range msgs {
			log.Printf("Exchange: %s", d.Exchange)
			log.Printf("Routing Key: %s", d.RoutingKey)
			log.Printf("Message: %s", d.Body)
			log.Printf("Consumer Tag: %s", d.ConsumerTag)
			log.Printf("Content Type: %s", d.ContentType)
		}
	}()

	log.Printf(" [*] Waiting for messages. To exit press CTRL+C")
	<-forever
}
