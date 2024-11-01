package main

import (
	"arch/cmd/runner"
	"arch/internal/config"
	"arch/internal/injector"
)

func main() {
	viperConfig := config.NewViper()
	app := injector.InitializeServer()
	// defer func() {
	// 	if rabbitMQClient, ok := app.(*config.RabbitMQClient); ok {
	// 		rabbitMQClient.Close()
	// 	}
	// }()

	runner.ShutdownApplication(app)
	runner.StartApplication(app, viperConfig)
	runner.CleanUpApplication()
}
