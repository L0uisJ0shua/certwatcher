package main

import (
	certrun "internal/runner"
	"pkg/certstream"
	types "pkg/types"
	yamlreader  "pkg/yamlreader"
	log "github.com/sirupsen/logrus"
	config "pkg/config"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/goflags"
	"strings"
	"os"
)

var ( 
	options = &types.Options{}
)

func main() {

	opt := options

    flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("This project is in active development not ready for production.")

	// templates configs
	flagSet.CreateGroup("templates", "Templates",
		flagSet.StringSliceVarP(&opt.Templates, "template", "t", nil, "List of template or template directory to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opt.Keywords, "keyword", "", nil, "Specify a YAML template to load the search words", goflags.FileCommaSeparatedStringSliceOptions),
    flagSet.BoolVar(&opt.Validate, "validate", false, "Validate the passed templates to certwatcher"),
	)
    // browser configs
	flagSet.CreateGroup("headless", "Headless",
		flagSet.BoolVar(&opt.Headless, "headless", false, "Enable templates that require headless browser support (root user on Linux will disable sandbox)"),
		flagSet.IntVar(&opt.PageTimeout, "timeout", 30, "Seconds to wait for each page in headless mode"),
		flagSet.BoolVar(&opt.PageScreenShot, "screenshot", false, "Configure the program to capture screenshots"),
	)
	// debug
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&opt.Verbose, "vv", false, "Display templates loaded for scan"),
		flagSet.BoolVar(&opt.Debug, "vvv", false, "Display templates loaded and debug information"),
		flagSet.BoolVar(&opt.Version, "version", false, "Show certwatcher version"),
	)

	if err := flagSet.Parse(); err != nil {
		return
	}

	certrun.Banner()

	var keywords types.Keywords
	// Debug
	gologger.Info().Msgf("Loading Default Keywords Templates")
	log.Info("Loading a default keywords Templates")
	err := yamlreader.ReadYAMLFile(config.Keywords, &keywords)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	
	// configurações padrão (nível de log, formatador, saída)
	log.SetLevel(log.DebugLevel)
	logger := 0

	certStream := certstream.NewCertStream()

	gologger.Info().Msgf("Capturing the certificates for analysis")

	for event := range certStream.GetCertificates() {
		for _, keyword := range keywords.Info.Keywords {
			if strings.Contains(strings.ToLower(event.Data.LeafCert.Subject.Domain), strings.ToLower(keyword)) {
				domains := log.Fields{
					"Domains": event.Data.LeafCert.Subject.Domain,
					"Certificates": logger,
				}

				log.WithFields(domains).Debug("[INFO] Certificates and Domains for analysis")

				logger++
				break
			}
	}
}

}