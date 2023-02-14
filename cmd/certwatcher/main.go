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


type CertificateInfo struct {
	Domains      string
	Certificates interface{}
	Keyword string
}

func main() {

	opt := options

    flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("This project is in active development not ready for production.")

	// templates configs
	flagSet.CreateGroup("templates", "Templates",
		flagSet.StringSliceVarP(&opt.Templates, "template", "t", nil, "List of template or template directory to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opt.Keywords, "keyword", "", "", "Specify a YAML template to load the search words"),
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
		flagSet.BoolVar(&opt.Debug, "vv", false, "Display templates loaded and debug information"),
		flagSet.BoolVar(&opt.Version, "version", false, "Show certwatcher version"),
	)

	if err := flagSet.Parse(); err != nil {
		return
	}

	certrun.Banner()


	if opt.Debug {
		log.SetLevel(log.DebugLevel)
	} else if opt.Version {
		log.Info("Certwatcher Version %s", config.Version)
		os.Exit(1)
	}

	var keywords types.Keywords
	
	if len(opt.Keywords) > 0 {
		// Debug
		gologger.Info().Msgf("Loading Custom Keywords Templates")
		log.Debug("Loading a Custom keywords Templates")
		err := yamlreader.ReadYAML(opt.Keywords, &keywords)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

	} else {
		 // Debug
		gologger.Info().Msgf("Loading Default Keywords Templates")
		log.Debug("Loading a default keywords Templates")
		err := yamlreader.ReadYAML(config.Keywords, &keywords)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	}
	
	logger := 0

	certStream := certstream.NewCertStream()

	gologger.Info().Msgf("Capturing the certificates for analysis")

	for event := range certStream.GetCertificates() {
		for _, keyword := range keywords.Info.Keywords {
			if strings.Contains(strings.ToLower(event.Data.LeafCert.Subject.Domain), strings.ToLower(keyword)) {

				ci := CertificateInfo{
					Domains:      event.Data.LeafCert.Subject.Domain,
					Certificates: logger,
					Keyword: strings.ToLower(keyword),
				}

				gologger.Info().Msgf("domain(s) matching: %s", ci.Domains)
				gologger.Info().Msgf("%d certificate(s) issued\n", ci.Certificates)
				gologger.Info().Msgf("keyword(s) matching: %s", ci.Keyword)
				break
			}
		}
		logger++
	}

}