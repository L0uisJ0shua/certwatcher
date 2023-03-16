package core

import (
    "strings"

    log "github.com/projectdiscovery/gologger"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"

    "pkg/templates"
    "pkg/types"
)

type Protocols struct {
    DNS string
    SSL string
    Log string
}

var protocols = Protocols{
    DNS: "dns",
    SSL: "ssl",
    Log: "log",
}

// LogMessage logs a message with the specified ID, severity, and domain,
// along with an array of message strings.
func LogMessage(id, name string, severity severity.Severity, domain string, message []string) {
    log.Info().Msgf("%s\n", templates.Message(id, name, severity, domain, message))
}

// Certificate checks for TLD matches and logs messages using LogMessage
func Log(certificates types.Message, keyword string, severity severity.Severity, tlds []string, matchers []string) {
    msg(certificates, keyword, severity, strings.Join(certificates.Domains, ","), strings.Split(certificates.Issuer, ","))
}

// LogError logs an error along with a message using the log package
func LogError(err error, message string) {
    log.Warning().Msgf("Error: %v - %s\n", err, message)
}

// Msg logs multiple messages using LogMessage
func msg(certificates types.Message, keyword string, severity severity.Severity, domains string, issuer []string) {

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
        LogMessage(log.id, log.name, severity, certificates.Domain, log.message)
    }
}