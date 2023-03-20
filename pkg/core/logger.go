package core

import (
    "strings"

    log "github.com/projectdiscovery/gologger"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "github.com/logrusorgru/aurora"
    "pkg/types"
    "internal/colorizer"
    "fmt"
)

var protocols = &types.Protocols{
    DNS: "dns",
    SSL: "ssl",
    Log: "log",
}

// This package includes a Logger function, which returns a beautified log string for a template, based on the provided parameters.
var (
    Colorizer aurora.Aurora
)

func init() {
    Colorizer = aurora.NewAurora(true)
}

// The package also includes a Colorizer object, which is used to colorize output for the Logger function. 
// The object is initialized in the package's init() function, using the "aurora" package for ANSI color output.
func Message(id string, name string, templateSeverity severity.Severity, domain string, options []string) string {

    return fmt.Sprintf("[%s] [%s] [%s] %s %s",
        Colorizer.BrightGreen(id).String(),
        Colorizer.BrightBlue(name).String(),
        colorizer.GetSeverityColor(templateSeverity),
        Colorizer.White(domain).String(),
        Colorizer.Cyan(options))
}

// LogMessage logs a message with the specified ID, severity, and domain,
// along with an array of message strings.
func Log(id, name string, severity severity.Severity, domain string, message []string) {
    log.Info().Msgf("%s\n", Message(id, name, severity, domain, message))
}

// Certificate checks for TLD matches and logs messages using LogMessage
func LogCertificates(certificates types.Message, keyword string, severity severity.Severity, tlds []string, matchers []string) {
    logMessages(certificates, keyword, severity, strings.Join(certificates.Domains, ","), strings.Split(certificates.Issuer, ","))
}
// logMessages logs multiple messages using LogMessage
func logMessages(certificates types.Message, keyword string, severity severity.Severity, domains string, issuer []string) {

    var logs []struct {
        id      string
        name    string
        message []string
    }

    logs = append(logs, struct {
        id      string
        name    string
        message []string
    }{
        id:      "ssl-dns-names",
        name:    protocols.DNS,
        message: strings.Split(domains, " "),
    })
    logs = append(logs, struct {
        id      string
        name    string
        message []string
    }{
        id:      "ssl-issuer",
        name:    protocols.SSL,
        message: issuer,
    })

    // Check if the keyword string is not empty
    if len(keyword) > 0 {
        logs = append(logs, struct {
            id      string
            name    string
            message []string
        }{
            id:      "keyword",
            name:    keyword,
            message: strings.Split(certificates.SubjectAltName, " "),
        })
    }

    logs = append(logs, struct {
        id      string
        name    string
        message []string
    }{
        id:      "source",
        name:    protocols.Log,
        message: strings.Split(certificates.Source, " "),
    })

    for _, log := range logs {
        Log(log.id, log.name, severity, certificates.Domain, log.message)
    }
}