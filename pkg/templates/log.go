package templates

import (
	"fmt"
	"internal/colorizer"
	"pkg/config"
	loggers "pkg/templates/log"
	"pkg/types"
	"pkg/utils"
	"strings"

	"github.com/logrusorgru/aurora"
	log "github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

var Protocolos = &types.Protocols{
	DNS:  "dns",
	SSL:  "ssl",
	Log:  "log",
	HTTP: "http",
}

type LogEntry struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Severity severity.Severity `json:"severity"`
	Domain   string            `json:"domain"`
	Types    string            `json:"types"`
	Message  string            `json:"message"`
	Options  []string          `json:"options"`
	Tags     []string          `json:"tags"`
	Authors  []string          `json:"authors"`
}

type LogEntryGroup struct {
	Template LogEntry
	CertsLog []LogEntry
}

// The package also includes a Colorizer object, which is used to colorize output for the Logger function.t.
var (
	Colorizer aurora.Aurora
)

func init() {
	Colorizer = aurora.NewAurora(true)
}

// Display templates information on load certwacher
func TemplateInfo(id, name string, authors []string, severity severity.Severity, tags []string) {

	logMsg := fmt.Sprintf("[%s] %s %s [%s] [%s]",
		aurora.Bold(id),
		aurora.Bold(name),
		aurora.Bold(Author(authors)),
		colorizer.GetSeverityColor(severity),
		aurora.BrightCyan(strings.Join(tags, ", ")))

	log.Info().Msgf("%s", logMsg)
}

// Display a single log information about match template
func Log(entries interface{}) {

	// Loaded Configuration File
	// This is default configuration
	config, _ := config.LoadConfig()
	logger, err := loggers.New(config.Log.File)
	if err != nil {
		log.Error().Msgf("%s", err)
		return
	}
	defer func() {
		if err := logger.Close(); err != nil {
			log.Error().Msgf("%s", err)
		}
	}()

	switch v := entries.(type) {
	case LogEntry:
		logMsg := fmt.Sprintf("[%s] [%s] [%s] %s [%s] [%s]",
			Colorizer.BrightGreen(v.ID).String(),
			Colorizer.BrightBlue(v.Name).String(),
			colorizer.GetSeverityColor(v.Severity),
			Colorizer.White(v.Domain).String(),
			Colorizer.BrightBlue(strings.Join(utils.Unique(v.Options), ", ")),
			Colorizer.BrightCyan(strings.Join(utils.Unique(v.Tags), ", ")))

		log.Info().Msgf("%s", logMsg)
		if err := logger.WriteLog(logMsg); err != nil {
			log.Error().Msgf("%s", err)
		}

	case LogEntryGroup:
		// log template entry
		templateLog := v.Template
		logMsg := fmt.Sprintf("[%s] [%s] [%s] %s [%s] [%s]",
			Colorizer.BrightGreen(templateLog.ID).String(),
			Colorizer.BrightBlue(templateLog.Name).String(),
			colorizer.GetSeverityColor(templateLog.Severity),
			Colorizer.White(templateLog.Domain).String(),
			Colorizer.BrightBlue(strings.Join(utils.Unique(templateLog.Options), ", ")),
			Colorizer.BrightCyan(strings.Join(utils.Unique(templateLog.Tags), ", ")))
		log.Info().Msgf("%s", logMsg)

		if err := logger.WriteLog(logMsg); err != nil {
			log.Error().Msgf("%s", err)
		}

		// log cert logs
		for _, certLog := range v.CertsLog {
			logArgs := []interface{}{
				Colorizer.BrightGreen(certLog.Name),
				Colorizer.BrightGreen(certLog.Types),
				Colorizer.BrightBlue(severity.Info),
				Colorizer.White(certLog.Domain),
				Colorizer.BrightCyan(certLog.Message),
			}

			logMsg := fmt.Sprintf("[%s] [%s] [%s] %s [%s]", logArgs...)
			log.Info().Msgf("%s", logMsg)
			if err := logger.WriteLog(logMsg); err != nil {
				log.Error().Msgf("%s", err)
			}
		}

	default:
		log.Error().Msgf("invalid entry type")
	}
}

// appendAtSignToAuthors appends @ before each author and returns the final string
func Author(authors []string) string {
	if len(authors) == 0 {
		return "@unknow"
	}

	values := make([]string, 0, len(authors))
	for _, k := range authors {
		if !strings.HasPrefix(k, "@") {
			values = append(values, fmt.Sprintf("@%s", k))
		} else {
			values = append(values, k)
		}
	}
	return strings.Join(values, ", ")
}
