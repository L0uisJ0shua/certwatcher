// Package logger provides logging functionality
package core

import (
    "strings"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "github.com/projectdiscovery/gologger"
    types "pkg/types"
    template "pkg/templates"
	utils "pkg/utils"
    "regexp"
    "fmt"
)

// LogMsg logs a message with the specified ID, severity, and domain,
// along with an array of message strings.
func LogMsg(id, name string, severity severity.Severity, domain string, message []string) {
    fmt.Printf("%s\n", template.Message(id, name, severity, domain, message))
}

// Certificate checks for TLD matches and logs messages using LoggLogMsger
func Certificate(certificates types.Message, keyword string, tlds []string) {
    // Check for TLD matches
    for _, tld := range tlds {
        if matched, _ := regexp.MatchString(tld, certificates.Domain); matched {
            gologger.Info().Msgf("Domain %s Matched TLDs (Top-Level Domains)", certificates.Domain)
            Message(certificates, keyword, utils.JoinWithCommas(certificates.Domains), strings.Split(certificates.Issuer, ","))
            return
        }
    }

    // Handle the case where no TLD or matcher match was found
    gologger.Info().Msgf("No Domain Matched TLDs (Top-Level Domains)")
    Message(certificates, keyword, utils.JoinWithCommas(certificates.Domains), strings.Split(certificates.Issuer, ","))
}

// Message logs multiple messages using LogMsg
func Message(certificates types.Message, keyword string, domains string, issuer []string) {
    logs := []struct {
        id       string
        name     string
        message  []string
    }{
        {"ssl-dns-names", "dns", strings.Split(domains, " ")},
        {"issuer", "ssl", issuer},
        {"keyword", keyword, strings.Split(certificates.SubjectAltName, " ")},
        {"source", "log", strings.Split(certificates.Source, " ")},
    }

    for _, log := range logs {
        LogMsg(log.id, log.name, severity.Info, certificates.Domain, log.message)
    }
}
