package colorizer

import (
    "github.com/logrusorgru/aurora"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

const (
    fgOrange uint8 = 208
)

func GetSeverityColor(templateSeverity severity.Severity) string {
    var method func(arg interface{}) aurora.Value
    switch templateSeverity {
    case severity.Info:
        method = aurora.Blue
    case severity.Low:
        method = aurora.Green
    case severity.Medium:
        method = aurora.Yellow
    case severity.High:
        method = func(stringValue interface{}) aurora.Value { return aurora.Index(fgOrange, stringValue) }
    case severity.Critical:
        method = aurora.Red
    default:
        method = aurora.White
    }

    return method(templateSeverity.String()).String()
}

func New() func(severity.Severity) string {
    return func(severity severity.Severity) string {
        return GetSeverityColor(severity)
    }
}
