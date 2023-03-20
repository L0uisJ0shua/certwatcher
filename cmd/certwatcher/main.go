package main

import (
	"os"
	goflags "github.com/projectdiscovery/goflags"
	log "github.com/projectdiscovery/gologger"
	levels "github.com/projectdiscovery/gologger/levels"
	types "pkg/types"
	config "pkg/config"
	runner "internal/runner"
	core "pkg/core"
	stream "pkg/stream"
)

var (
	options = &types.Options{}
	message = &types.Message{}
)

func init() {
	// Configures the logger to print the name of the file and the line
	// where the log was registered.
	log.DefaultLogger.SetMaxLevel(levels.LevelInfo)
}

func main() {

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("This project is in active development not ready for production.")

	// Templates configs
	flagSet.CreateGroup("templates", "Templates",
		flagSet.StringSliceVarP(&options.Templates, "template", "t", nil, "List of template or template directory to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&options.Validate, "validate", false, "Validate the passed templates to certwatcher"),
	)

	// Browser configs
	flagSet.CreateGroup("headless", "Headless",
		flagSet.BoolVar(&options.Headless, "headless", false, "Enable templates that require headless browser support (root user on Linux will disable sandbox)"),
		flagSet.IntVar(&options.PageTimeout, "timeout", 30, "Seconds to wait for each page in headless mode"),
		flagSet.BoolVar(&options.PageScreenShot, "screenshot", false, "Configure the program to capture screenshots"),
	)
	// Debug
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Verbose, "verbose", false, "display verbose information"),
		flagSet.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
		flagSet.BoolVar(&options.Version, "version", false, "show certwatcher version"),
	)

	runner.Welcome()

	err := flagSet.Parse()

	if err != nil {
		log.Fatal().Msgf("failed to parse command line flags: %s", err)
	}

	if options.Version {
	    log.Info().Msgf("Certwatcher version %s\n", config.Version)
	    os.Exit(0)
	}

	// Debug
	if options.Debug {
		log.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}

	if options.Verbose {
		log.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	
	}

	options := types.Options{
        Templates: options.Templates,
    }

    templates,paths,matchers := core.Templates(options)
    for _, template := range templates {
		stream.Certificates(template.Keywords, template.TLDs, matchers, template.Requests, template.Severity, paths, template.ID)
	}
}