package main

import (
	"arch/cmd/runner"
	"arch/internal/config"
	"arch/internal/injector"
)

func main() {
	viperConfig := config.NewViper()
	app := injector.InitializeServer()

	runner.ShutdownApplication(app)
	runner.StartApplication(app, viperConfig)
	runner.CleanUpApplication()
}
