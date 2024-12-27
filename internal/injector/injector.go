//go:build wireinject
// +build wireinject

package injector

import (
	"arch/internal/config"
	"arch/internal/delivery/http/controller"
	"arch/internal/delivery/http/middleware"
	"arch/internal/delivery/http/route"
	"arch/internal/gateway/producer"
	"arch/internal/repository"
	"arch/internal/usecase"

	"github.com/gofiber/fiber/v2"
	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type BootstrapApp struct {
	App    *fiber.App
	Redis  *redis.Client
	Config *viper.Viper
	Log    *logrus.Logger
}

// Create separate sets for each database connection provider
var AuthDatabaseSet = wire.NewSet(
	config.ProvideAuthDatabase, // For Kpi Database
)

var IthubDatabaseSet = wire.NewSet(
	config.ProvideIthubDatabase, // For Ithub Database
)

var configSet = wire.NewSet(
	config.NewViper,
	config.NewLogrus,
	config.NewValidator,
	config.NewRedis,
	config.NewJwtWrapper,
	config.NewAwsS3,
	AuthDatabaseSet,
	IthubDatabaseSet,
)
var repositorySet = wire.NewSet(repository.NewUserRepository, repository.NewClientRepository)
var rabbitMQProducerSet = wire.NewSet(producer.NewRabbitMQProducer)
var useCaseSet = wire.NewSet(usecase.NewAuthUseCase, usecase.NewUserUseCase, usecase.NewClientUseCase)
var controllerSet = wire.NewSet(controller.NewAuthController, controller.NewUserController, controller.NewClientController)
var middlewareSet = wire.NewSet(middleware.NewAuthJwtMiddleware)

func InitializeServer() *BootstrapApp {
	wire.Build(
		configSet,
		repositorySet,
		rabbitMQProducerSet,
		useCaseSet,
		controllerSet,
		middlewareSet,
		route.NewRouteApp,
		config.NewFiber,
		wire.Struct(new(BootstrapApp), "App", "Redis", "Config", "Log"),
	)
	return nil
}
