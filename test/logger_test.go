package main

import (
    "testing"

    "pkg/core"
    "pkg/types"

    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

func TestSingleMessage(t *testing.T) {
    // Call the function with some sample values
    core.Log("git-metadata-exposure", "http", severity.Info, "https://example.com", []string{"repositoryformatversion", "[core]"}, 400)

    // No need to assert anything in this case
    // If the function doesn't panic, it means it executed successfully
}

func TestGroupMessage(t *testing.T) {
    // Criar uma entrada de certificado para teste
    cert := types.Message{
        Domains:        []string{"example.com"},
        Issuer:         "Let's Encrypt, Digital Signature Trust Co.",
        SubjectAltName: "example.com, www.example.com",
        Source:         "https://example.com",
    }

    core.LogCertificates(cert, "dns", severity.Medium, []string{"com"}, []string{"1.1.1.1", "2.2.2.2"})

}
