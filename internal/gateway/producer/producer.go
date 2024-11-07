package producer

import (
	"context"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// InitializeConnection sets up the RabbitMQ connection
func initializeConnection(config *viper.Viper, log *logrus.Logger) (*amqp.Connection, *amqp.Channel, error) {
	host := config.GetString("rabbitmq.host")
	port := config.GetInt("rabbitmq.port")
	user := config.GetString("rabbitmq.user")
	password := config.GetString("rabbitmq.password")
	virtualHost := config.GetString("rabbitmq.virtual_host")
	dsn := fmt.Sprintf("amqp://%s:%s@%s:%d%s", user, password, host, port, virtualHost)

	connection, err := amqp.Dial(dsn)
	if err != nil {
		log.Errorf("Failed to connect to RabbitMQ: %v", err)
		return nil, nil, err
	}

	channel, err := connection.Channel()
	if err != nil {
		log.Errorf("Failed to open a channel: %v", err)
		connection.Close()
		return nil, nil, err
	}

	return connection, channel, nil
}

// DeclareQueue declares a queue with the given parameters
func declareQueue(channel *amqp.Channel, queueName string, log *logrus.Logger) (amqp.Queue, error) {
	q, err := channel.QueueDeclare(
		queueName,
		true,
		false,
		false,
		false,
		amqp.Table{"x-queue-type": "quorum"},
	)
	if err != nil {
		log.Errorf("Failed to declare a queue: %v", err)
		return amqp.Queue{}, err
	}
	return q, nil
}

// DeclareExchange declares an exchange with the given parameters
func declareExchange(channel *amqp.Channel, exchangeName string, log *logrus.Logger) error {
	err := channel.ExchangeDeclare(
		exchangeName,
		amqp.ExchangeDirect,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		log.Errorf("Failed to declare an exchange: %v", err)
		return err
	}
	return nil
}

type RabbitMQProducer struct {
	Config *viper.Viper
	Log    *logrus.Logger
}

func NewRabbitMQProducer(config *viper.Viper, log *logrus.Logger) *RabbitMQProducer {
	return &RabbitMQProducer{
		Config: config,
		Log:    log,
	}
}

// PublishMessage connects to RabbitMQ, declares a queue and an exchange, binds them, and publishes a message
func (r *RabbitMQProducer) PublishMessage(ctx context.Context, exchangeName, queueName, contentType string, message []byte) {
	// Establish connection and channel
	connection, channel, err := initializeConnection(r.Config, r.Log)
	if err != nil {
		r.Log.Fatalf("Failed to initialize RabbitMQ connection and channel: %v", err)
		return
	}
	defer connection.Close()
	defer channel.Close()

	// Declare the queue
	q, err := declareQueue(channel, queueName, r.Log)
	if err != nil {
		r.Log.Errorf("Failed to declare queue: %v", err)
		return
	}

	// Declare the exchange
	err = declareExchange(channel, exchangeName, r.Log)
	if err != nil {
		r.Log.Errorf("Failed to declare exchange: %v", err)
		return
	}

	// Bind queue to the exchange
	err = channel.QueueBind(
		q.Name,
		q.Name,
		exchangeName,
		false,
		nil,
	)
	if err != nil {
		r.Log.Errorf("Failed to bind exchange to queue: %v", err)
		return
	}

	// Set a 5-second timeout for publishing
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Prepare the message
	payload := amqp.Publishing{
		ContentType: contentType,
		Body:        message,
	}

	// Publish the message
	err = channel.PublishWithContext(
		ctx,
		exchangeName,
		q.Name,
		false,
		false,
		payload,
	)
	if err != nil {
		r.Log.Errorf("Failed to publish message: %v", err)
		return
	}

	r.Log.Infof("Message published successfully route to : %s", q.Name)
}
