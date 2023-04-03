package main

import (
	runner "internal/runner"
	"os"
	"os/signal"
	core "pkg/core"
	stream "pkg/stream"
	types "pkg/types"
	"syscall"

	log "github.com/projectdiscovery/gologger"
)

func main() {

	// Parse CLI command line options
	options := runner.ParseOptions()

	// Call the function that executes the templates here, using the options defined in "options"
	template := types.Options{
		Templates: options.Templates,
	}

	templates := core.Templates(template)
	stream.Certificates(templates)
}

func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// Setup close handler
	go func() {
		<-c
		log.Info().Msgf("\rCtrl+C pressed in Terminal, Exiting...\n")
		os.Exit(0)
	}()
}
