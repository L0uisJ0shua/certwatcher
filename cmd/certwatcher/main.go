package main

import (
	"os"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	log "github.com/sirupsen/logrus"
	"github.com/projectdiscovery/gologger/levels"
	types "pkg/types"
	config "pkg/config"
	runner "internal/runner"
	"pkg/certstream"
	"pkg/matchers"
	"encoding/json"
	core "pkg/core"
	"time"
	_"fmt"
)

var (
	options = &types.Options{}
	message = &types.Message{}
)

func init() {
	// Configures the logger to print the name of the file and the line
	// where the log was registered.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
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
		log.Fatalf("failed to parse command line flags: %s", err)
	}

	if options.Version {
	    gologger.Info().Msgf("Certwatcher version %s\n", config.Version)
	    os.Exit(0)
	}

	// Debug
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}

	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	
	}
	options := types.Options{
        Templates: options.Templates,
        // other options
    }
    keywords, tlds, _ := core.Templates(options)

	// // Initializes the variable 'certs' with the value of zero.
	certs := 0

	// // Prints an informational message indicating that 
	// // the code is capturing certificates for analysis.
	gologger.Info().Msgf("Capturing the certificates for analysis\n\n")
	
	// // Capturing certificates from a CertStream, real-time 
	// // feed of newly issued SSL/TLS certificates.
	certwatcher := certstream.NewCertStream()
	
	// // Iterates over each certificate 
	// // event received from CertStream.
	for event := range certwatcher.GetCertificates() { 

	// 	// Converts the 'event.Data' object to JSON format and checks if there is any error.
		_, err := json.MarshalIndent(event.Data, "", "  ")
		if err != nil {
			gologger.Fatal().Msgf("Error marshaling jq data to JSON")
		}

		leafCert := event.Data.LeafCert
		data := event.Data

	    certificates := types.Message{
	        Domain:     leafCert.Subject.CN,
	        Domains:    leafCert.AllDomains,
	        Issuer: leafCert.Issuer.O,
	        Source:     data.Source.Name,
	        SubjectAltName: leafCert.Extensions.SubjectAltName,
	    }

		// Prints a debug message indicating the origin of the event.
		gologger.Debug().Msgf("Event receive from %s", certificates.Source)
		gologger.Debug().Msgf("Number of certificates issued %d", certs)

		// Iterates over each specified keyword.
		for _, keyword := range keywords {
			// Check if the keyword matches the domain
			if matchers.Contains(certificates.Domain, keyword) {

				gologger.Info().Msgf("Suspicious Activity found at %s", time.Now().Format("01-02-2006 15:04:05"))
				gologger.Info().Msgf("Number of certificates issued %d", certs)

				core.Certificate(certificates, keyword, tlds)
			}
		}
		// Increments the counter for the number of certificates processed.
		certs++
	}
}