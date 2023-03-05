package core

import (
    log "github.com/projectdiscovery/gologger"
    "strings"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "pkg/templates"
    "pkg/types"
)

// LogMessage logs a message with the specified ID, severity, and domain,
// along with an array of message strings.
func LogMessage(id, name string, severity severity.Severity, domain string, message []string) {
    log.Info().Msgf("%s\n", templates.Message(id, name, severity, domain, message))
}

// Certificate checks for TLD matches and logs messages using LogMessage
func Log(certificates types.Message, keyword string, severity severity.Severity, tlds []string, matchers []string) {
    Msg(certificates, keyword, severity, strings.Join(certificates.Domains, ","), strings.Split(certificates.Issuer, ","))
}

// LogError logs an error along with a message using the log package
func LogError(err error, message string) {
    log.Warning().Msgf("Error: %v - %s\n", err, message)
}

// Message logs multiple messages using LogMessage
func Msg(certificates types.Message, keyword string, severity severity.Severity, domains string, issuer []string) {

    // Type of protocols
    protocols := types.Protocols{
        DNS: "dns",
        SSL: "ssl",
        Log: "log",
    }

    logs := []struct {
        id      string
        name    string
        message []string
    }{
        {"ssl-dns-names", protocols.DNS, strings.Split(domains, " ")},
        {"ssl-issuer", protocols.SSL, issuer},
        {"keyword", keyword, strings.Split(certificates.SubjectAltName, " ")},
        {"source", protocols.Log, strings.Split(certificates.Source, " ")},
    }

    for _, log := range logs {
        LogMessage(log.id, log.name, severity, certificates.Domain, log.message)
    }
}
