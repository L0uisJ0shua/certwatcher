package main

import (
    "testing"
    "pkg/types"
    matcher "pkg/matchers"
)

func TestMatcher(t *testing.T) {

    keywords := []string{"apple", "amazon", "bradesco"}
    tlds := []string{"net", "org", "com"}
    matchers := []string{"IETFIETF", "amazon", "bradesco"}
    template := matcher.New(keywords, tlds, matchers)

    // Initializes the variable 'certs' with the value of zero.
    certs := 0

    // Match a certificate with a matching TLD only
    certificates := types.Message{
        Domain:         "www.amazon.com",
        Domains:        []string{"amazon.com", "www.amazon.com"},
        SubjectAltName: "amazon.com",
        Issuer:         "Amazon Issuer",
        Source:         "Amazon",
    }

    template.Match(certificates, keywords, tlds, matchers, certs, "Laravel Debug Method Enabled", "High")

    // Match a certificate with a matching TLD and matcher
    certificates = types.Message{
        Domain:         "www.ietf.org",
        Domains:        []string{"ietf.org", "www.ietf.org"},
        SubjectAltName: "ietf.org",
        Issuer:         "IETF Issuer",
        Source:         "IETF Domain",
    }
   
    template.Match(certificates, keywords, tlds, matchers, certs, "Laravel Debug Method Enabled", "High")

    // Match a certificate with a matching TLD and keyword
    certificates = types.Message{
        Domain:         "www.apple.com",
        Domains:        []string{"apple.com", "www.apple.com"},
        SubjectAltName: "apple.com",
        Issuer:         "Apple Issuer",
        Source:         "Lets Encrypt",
    }
    
    template.Match(certificates, keywords, tlds, matchers, certs, "Laravel Debug Method Enabled", "High")

    // Match a certificate with a matching TLD, keyword, and matcher
    certificates = types.Message{
        Domain:         "bradesco.reativacaodechave.com",
        Domains:        []string{"bradesco.reativacaodechave.com", "www.bradesco.reativacaodechave.com"},
        SubjectAltName: "bradesco.reativacaodechave.com",
        Issuer:         "Google Issuer",
        Source:         "Google Domain",
    }

    template.Match(certificates, keywords, tlds, matchers, certs, "Laravel Debug Method Enabled", "High")
}

