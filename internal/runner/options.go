package runner

import (
	"os"
	"strings"

	"pkg/config"

	"github.com/projectdiscovery/goflags"
	log "github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type Options struct {
	Templates      goflags.StringSlice
	Generate       goflags.StringSlice
	Validate       bool
	Output         string
	Json           bool
	Headless       bool
	PageTimeout    int
	PageScreenShot bool
	Verbose        bool
	Debug          bool
	Version        bool
	Retries        int
	Timeout        int
}

func ParseOptions() *Options {

	// Initialized Options
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("This project is in active development not ready for production.")

	// Templates configs
	flagSet.CreateGroup("templates", "Templates",
		flagSet.StringSliceVarP(&options.Templates, "template", "t", nil, "List of template or template directory to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&options.Validate, "validate", false, "Validate the passed templates to certwatcher"),
		flagSet.StringSliceVarP(&options.Generate, "generate", "g", nil, "Generate a new template with the provided name Powered by OpenAI (input: stdin,string,file)", goflags.CommaSeparatedStringSliceOptions),
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

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&options.Json, "json", "j", false, "write output in json(line) format"),
	)

	// Parse flagSet
	if err := flagSet.Parse(); err != nil {
		log.Fatal().Msgf("%s\n", err)
	}

	// Loaded Configuration File
	// This is default configuration
	c, err := config.LoadConfig()

	if err != nil {
		log.Fatal().Msgf("Error loading configuration: %s", err)
	}

	// Default Configuration Output
	options.SetLogLevel(&c)

	// If the user desires verbose output, show verbose output
	if options.Version {
		log.Info().Msgf("Certwatcher version %s\n", config.Version)
		os.Exit(0)
	}

	// Show the certwatcher banner
	ShowBanner()

	return options
}

// SetLogLevel sets the logging level based on the configuration
func (options *Options) SetLogLevel(config *config.Config) {
	// Switch based on the configuration values
	switch strings.ToLower(config.Log.Level) {
	case "debug":
		log.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	case "verbose":
		log.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	case "warning":
		log.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	case "error":
		log.DefaultLogger.SetMaxLevel(levels.LevelError)
	default:
		if options.Debug {
			log.DefaultLogger.SetMaxLevel(levels.LevelDebug)
		} else {
			log.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		}
	}
}
