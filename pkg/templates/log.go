package templates

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"internal/colorizer"
)

// This package includes a Certslogger function, which returns a beautified log string for a template, based on the provided parameters.

var (
	Colorizer aurora.Aurora
)

func init() {
	Colorizer = aurora.NewAurora(true)
}

// The package also includes a Colorizer object, which is used to colorize output for the Certslogger function. 
// The object is initialized in the package's init() function, using the "aurora" package for ANSI color output.
func Certslogger(id string, name string, templateSeverity severity.Severity, domain string, options string) string {

	return fmt.Sprintf("[%s] [%s] [%s] %s [%s]",
		Colorizer.BrightGreen(id).String(),
		Colorizer.BrightBlue(name).String(),
		colorizer.GetSeverityColor(templateSeverity),
		Colorizer.White(domain).String(),
		Colorizer.Cyan(options))
}
