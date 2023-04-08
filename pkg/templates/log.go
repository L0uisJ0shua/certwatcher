package templates

import (
	"fmt"
	"internal/colorizer"
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
	ID       string
	Name     string
	Severity severity.Severity
	Domain   string
	Types    string
	Message  string
	Options  []string
	Tags     []string
	Authors  []string
}

// The package also includes a Colorizer object, which is used to colorize output for the Logger function.t.
var (
	Colorizer         aurora.Aurora
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
func Log(entry LogEntry) {
	log.Info().Msgf("[%s] [%s] [%s] %s [%s] [%s]",
		Colorizer.BrightGreen(entry.ID).String(),
		Colorizer.BrightBlue(entry.Name).String(),
		colorizer.GetSeverityColor(entry.Severity),
		Colorizer.White(entry.Domain).String(),
		Colorizer.BrightBlue(strings.Join(utils.Unique(entry.Options), ", ")),
		Colorizer.BrightCyan(strings.Join(utils.Unique(entry.Tags), ", ")))
}

func CertsLog(entries []LogEntry, args ...interface{}) {
	for _, entry := range entries {
		logArgs := []interface{}{
			Colorizer.BrightGreen(entry.Name),
			Colorizer.BrightGreen(entry.Types),
			Colorizer.BrightBlue(severity.Info),
			Colorizer.White(entry.Domain),
			Colorizer.BrightCyan(entry.Message),
		}
		log.Info().Msgf("[%s] [%s] [%s] %s [%s]", logArgs...)
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
