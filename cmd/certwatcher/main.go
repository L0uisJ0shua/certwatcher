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
	levels "github.com/projectdiscovery/gologger/levels"
)

func main() {

	// Faz o parse das opções da linha de comando CLI
	options := runner.ParseOptions()

	// Chamar a função que executa os templates aqui, usando as opções definidas em "options"
	template := types.Options{
		Templates: options.Templates,
	}

	templates, _, _ := core.Templates(template)
	stream.Certificates(templates)
}

func init() {

	// Configures the logger to print the name of the file and the line
	// where the log was registered.
	log.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// Setup close handler
	go func() {
		<-c
		log.Info().Msg("\rCtrl+C pressed in Terminal, Exiting...")
		os.Exit(0)
	}()
}
