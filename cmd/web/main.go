// package main

// import (
// 	"arch/internal/injector"
// 	"fmt"
// 	"os"
// 	"os/signal"
// 	"syscall"
// )

// func main() {
// 	bootstrapApp := injector.InitializeServer()

// 	// Listen from a different goroutine
// 	appPort := bootstrapApp.Config.GetUint16("app.port")
// 	go func() {
// 		if err := bootstrapApp.App.Listen(fmt.Sprintf(":%d", appPort)); err != nil {
// 			bootstrapApp.Log.Panic(err)
// 		}
// 	}()

// 	c := make(chan os.Signal, 1)
// 	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

// 	_ = <-c
// 	fmt.Println("Gracefully shutting down...")
// 	_ = bootstrapApp.App.Shutdown()

// 	fmt.Println("Running cleanup tasks...")

// 	// Your cleanup tasks go here
// 	bootstrapApp.Redis.Close()
// 	fmt.Println("Fiber was successful shutdown.")

// 	// runner.ShutdownApplication(app)
// 	// runner.StartApplication(app, viperConfig)
// 	// runner.CleanUpApplication()
// }

package main

import (
	"arch/internal/injector"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	bootstrapApp := injector.InitializeServer()

	// Listen from a different goroutine
	appPort := bootstrapApp.Config.GetUint16("app.port")
	go func() {
		if err := bootstrapApp.App.Listen(fmt.Sprintf(":%d", appPort)); err != nil {
			bootstrapApp.Log.Panic(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	<-c
	fmt.Println("Gracefully shutting down...")
	if err := bootstrapApp.App.Shutdown(); err != nil {
		bootstrapApp.Log.Panic(err)
	}

	fmt.Println("Running cleanup tasks...")

	// Your cleanup tasks go here
	bootstrapApp.Redis.Close()
	fmt.Println("Fiber was successful shutdown.")

	// runner.ShutdownApplication(app)
	// runner.StartApplication(app, viperConfig)
	// runner.CleanUpApplication()
}
