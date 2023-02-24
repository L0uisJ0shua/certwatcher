package utils

import (
    "strings"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "github.com/projectdiscovery/gologger"
    types "pkg/types"
    template "pkg/templates"
    "regexp"
    "fmt"
)

// JoinWithCommas junta uma lista de strings com vírgulas
func JoinWithCommas(strs []string) string {
    return strings.Join(strs, ",")
}

func JoinWithAt(name string) string {
    names := strings.Split(name, " ")
    var Author []string
    for _, name := range names {
        Author = append(Author,  strings.ToLower(name))
    }
    return "@" + strings.Join(Author, "")
}

func Logger(id string, name string, severity severity.Severity, domain string, message []string) {
    fmt.Printf("%s\n", template.Message(id, name, severity, domain, message))
}

func Certificate(certificates types.Message, keyword string, tlds []string) {

    hasMatch := false

    domains := JoinWithCommas(certificates.Domains)

    // Check for TLD matches
    if len(tlds) > 0 {
        for _, tld := range tlds {
            if matched, _ := regexp.MatchString(tld, certificates.Domain); matched {
                gologger.Info().Msgf("Domain %s matched TLD %s", certificates.Domain, tld)
                Message(certificates, keyword, domains)
                hasMatch = true
                break
            }
        }
    }

    // Handle the case where no TLD or matcher match was found
    if !hasMatch {
        gologger.Info().Msgf("No TLD or Matcher match found in the template")
        Message(certificates, keyword, domains)
    }
}

func Message(certificates types.Message, keyword string, domains string) {
    Logger("ssl-dns-names", "dns", severity.Info, certificates.Domain, strings.Split(domains, " "))
    Logger("issuer", "ssl", severity.Info, certificates.Domain, strings.Split(certificates.Aggregated, ","))
    Logger("caa-issuer", "ssl", severity.Info, certificates.Domain, strings.Split(certificates.CaIssuer, " "))
    Logger("keyword", keyword, severity.Info, certificates.Domain, strings.Split(certificates.SubjectAltName, " "))
    Logger("source", "log", severity.Info, certificates.Domain, strings.Split(certificates.Source, " "))
}