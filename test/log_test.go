package main

import (
    "fmt"
    "strings"
    "testing"

    "pkg/templates"
    "pkg/utils"

    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

func TestSingleMessage(t *testing.T) {
    // Create template LogEntry
    template := templates.LogEntry{
        ID:       "google-api-keys",
        Name:     templates.Protocolos.HTTP,
        Severity: severity.High,
        Tags:     utils.Unique([]string{"api", "keys", "token", "token"}),
        Domain:   "yahoo.com",
        Options:  []string{"tags"},
        // Adicionar outras entradas de informação de modelo aqui...
    }

    // Call the function with some sample values
    templates.Log(template)

    // No need to assert anything in this case
    // If the function doesn't panic, it means it executed successfully
}

func TestGroupMessage(t *testing.T) {

    // Create Certificates LogEntry
    certLog := []templates.LogEntry{
        {
            Name:    "ssl-dns-names",
            Types:   templates.Protocolos.DNS,
            Domain:  "www.google.com",
            Message: strings.Join([]string{}, ", "),
        },

        {
            Name:    "ssl-issuer",
            Types:   templates.Protocolos.SSL,
            Domain:  "google.com",
            Message: "Lets Encrypt",
        },
        {
            Name:    "source",
            Types:   templates.Protocolos.Log,
            Domain:  "google.com",
            Message: "Google Log's",
        },
    }
    // Call the function with some sample values
    templates.CertsLog(certLog)

}

func TestLog(t *testing.T) {
    // Define test cases
    testCases := []struct {
        id          string
        name        string
        authors     []string
        description string
        severity    severity.Severity
        tags        []string
        expected    string
    }{
        {
            id:       "git-config-exposure",
            name:     "Git Configuration Exposure",
            authors:  []string{"Charlie", "Richard", "Bruno", "@twitter/drfabiocastro"},
            severity: severity.Medium,
            tags:     []string{"git", "config", "file", "exposure"},
        },
        {
            id:       "stripe-secret-key",
            name:     "Stripe API Tokens",
            authors:  []string{"Charlie"},
            severity: severity.Low,
            tags:     []string{"exposure", "token", "payments", "stripe"},
        },
        {
            id:       "shopify-app-secret",
            name:     "Shopify App Secret",
            authors:  []string{},
            severity: severity.High,
            tags:     []string{"test", "example", "testing"},
        },
    }

    // Loop through test cases
    for _, tc := range testCases {
        t.Run(fmt.Sprintf("%s %s", tc.id, tc.name), func(t *testing.T) {
            // Call Log function
            templates.TemplateInfo(tc.id, tc.name, tc.authors, tc.severity, tc.tags)
        })
    }
}
