package runner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

func StartApplication(r *fiber.App, viper *viper.Viper) {
	// Start the server
	appPort := viper.GetUint16("app.port")
	err := r.Listen(fmt.Sprintf(":%d", appPort))
	if err != nil {
		panic(err)
	}

}

func ShutdownApplication(r *fiber.App) {
	// Implement graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-ctx.Done()
		log.Println("Gracefully shutting down...")
		r.Shutdown()
		stop()
	}()
}

func CleanUpApplication() {
	log.Println("Running cleanup tasks...")
	// wait 2 seconds for the server to shutdown
	time.Sleep(2 * time.Second)
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	log.Println("Finish cleanup tasks...")
}
