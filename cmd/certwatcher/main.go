package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drfabiocastro/certwatcher/pkg/config"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	log "github.com/sirupsen/logrus"

	"internal/runner"
	"pkg/certstream"
	"pkg/templates"
	types "pkg/types"
	yaml "pkg/yamlreader"
)

var (
	options = &types.Options{}
)

type Data struct {
	id      string
	Name    string
	Type    string
	Domain  string
	Options string
	Issue   string
}

func init() {
	// Configures the logger to print the name of the file and the line
	// where the log was registered.
	log.SetReportCaller(false)
	// Configures the format of the log output.
	// log.SetFormatter(&log.JSONFormatter{})
	// Configures the log output to stdout.
	log.SetOutput(os.Stdout)

}

func main() {

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("This project is in active development not ready for production.")

	// templates configs
	flagSet.CreateGroup("templates", "Templates",
		flagSet.StringSliceVarP(&options.Templates, "template", "t", nil, "List of template or template directory to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Keywords, "keyword", "", []string{"keywords/fas-keywords-default.yaml"}, "Specify a YAML template to load the search words", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&options.Validate, "validate", false, "Validate the passed templates to certwatcher"),
	)
	// browser configs
	flagSet.CreateGroup("headless", "Headless",
		flagSet.BoolVar(&options.Headless, "headless", false, "Enable templates that require headless browser support (root user on Linux will disable sandbox)"),
		flagSet.IntVar(&options.PageTimeout, "timeout", 30, "Seconds to wait for each page in headless mode"),
		flagSet.BoolVar(&options.PageScreenShot, "screenshot", false, "Configure the program to capture screenshots"),
	)
	// debug
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.VerboseVerbose, "vv", false, "display templates loaded for scan"),
		flagSet.BoolVar(&options.Verbose, "verbose", false, "display verbose information"),
		flagSet.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
		flagSet.BoolVar(&options.Version, "version", false, "show certwatcher version"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatal("exit ")
	}

	runner.Welcome()

	// Display version
	if options.Version {
		log.Info("Current Version: \n", config.Version)
		os.Exit(0)
	}
	// Debug
	if options.Debug {
		// Only log the warning severity or above.
		log.SetLevel(log.DebugLevel)
		log.Debug("debug mode enabled")
	}

	if options.Verbose {
		// Only log the warning severity or above.
		log.SetLevel(log.InfoLevel)
		log.Info("verbose mode enabled")
	}

	// Show how many keywords have been loaded.
	gologger.Info().Msgf("Keywords have been loaded %d", len(options.Keywords))

	// Lendo vários arquivos YAML e concatenando em um slice de structs
	// Percorre o slice e exibe os dados do YAML de cada item

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	var keywords []string

	for _, t := range options.Keywords {
		directory := filepath.Join(home,".certwatcher-templates", t)
		// Use directory here to access the template directory
		log.Debug("template keywords directory", directory)

		var template types.Keywords
		err := yaml.ReadYAML(directory, &template)
		if err != nil {
			log.Info(err)
		}

		keywords = append(keywords, template.Info.Keywords...)
	}

	logger := 0

	certStream := certstream.NewCertStream()

	timerFunc := func() {
		gologger.Info().Msgf("Number of certificates issued %d", logger)
	}

	// Define a duração do intervalo de tempo do timer
	interval := 30 * time.Second

	// Cria o timer e executa a função a cada intervalo de tempo
	timer := time.NewTicker(interval)
	defer timer.Stop()

	gologger.Info().Msgf("Capturing the certificates for analysis")

	for event := range certStream.GetCertificates() {

		Message := Data{
			Domain:  event.Data.LeafCert.Subject.CN,
			Options: event.Data.LeafCert.Extensions.SubjectAltName,
			Issue: strings.Replace(event.Data.LeafCert.Extensions.AuthorityInfoAccess, "\n", "", -1),
		}

		for _, keyword := range keywords {
			if strings.Contains(strings.ToLower(Message.Domain), strings.ToLower(keyword)) {
				fmt.Printf("%s\n",
					templates.Certslogger("ssl-dns-names", "dns", severity.Info, Message.Domain, string(Message.Options)))
				fmt.Printf("%s\n",
					templates.Certslogger("caa-issuer", "ssl", severity.Info, Message.Domain, Message.Issue))
				fmt.Printf("%s\n",
					templates.Certslogger("keyword", keyword, severity.Info, Message.Domain, string(Message.Options)))
			}
		}
		
		logger++
		
		select {
		case <-timer.C:
			timerFunc()
		default:
		}
	}
}
