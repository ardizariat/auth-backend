//go:build wireinject
// +build wireinject

package injector

import (
	"arch/internal/config"
	"arch/internal/delivery/http/controller"
	"arch/internal/delivery/http/middleware"
	"arch/internal/delivery/http/route"
	"arch/internal/repository"
	"arch/internal/usecase"

	"github.com/gofiber/fiber/v2"
	"github.com/google/wire"
)

var configSet = wire.NewSet(config.NewViper, config.NewLogger, config.NewDatabase, config.NewValidator, config.NewRedis, config.NewJwtWrapper)
var repositorySet = wire.NewSet(repository.NewUserRepository)
var useCaseSet = wire.NewSet(usecase.NewAuthUseCase)
var controllerSet = wire.NewSet(controller.NewAuthController)
var middlewareSet = wire.NewSet(middleware.NewAuthJwtMiddleware)

func InitializeServer() *fiber.App {
	wire.Build(configSet, repositorySet, useCaseSet, controllerSet, middlewareSet, route.NewRouteApp, config.NewFiber)
	return nil
}
