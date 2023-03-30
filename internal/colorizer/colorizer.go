package colorizer

import (
    "strings"

    "github.com/logrusorgru/aurora"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

const (
    fgOrange uint8 = 208
)

func parseSeverityString(severityStr string) severity.Severity {
    switch strings.ToLower(severityStr) {
    case "info":
        return severity.Info
    case "low":
        return severity.Low
    case "medium":
        return severity.Medium
    case "high":
        return severity.High
    case "critical":
        return severity.Critical
    default:
        return severity.Unknown
    }
}

func getSeverityValue(severityValue interface{}) severity.Severity {
    if severityStr, ok := severityValue.(string); ok {
        return parseSeverityString(severityStr)
    }
    return severityValue.(severity.Severity)
}

func GetSeverityColor(templateSeverity interface{}) string {
    severityValue := getSeverityValue(templateSeverity)
    var method func(arg interface{}) aurora.Value
    switch severityValue {
    case severity.Info:
        method = aurora.BrightBlue
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

    return method(severityValue.String()).String()
}

func New() func(severityValue interface{}) string {
    return func(severityValue interface{}) string {
        return GetSeverityColor(severityValue)
    }
}
