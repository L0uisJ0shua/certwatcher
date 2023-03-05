package main

import (
	"testing"
	"pkg/core"
	"pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

// Cache


func Log(t *testing.T) {

	// cache := core.NewHTTPCache()

	// Test with empty TLDs and Matchers
	certificates := types.Message{
		Domain:  "example.com",
		Domains: []string{"example.com"},
		Issuer:  "Let's Encrypt",
		Source:  "Google Inc Logs",
		SubjectAltName: "DNS*.example.com, www.example.com",
	}

	var keyword = "example"
	tlds := []string{}
	matchers := []string{}
	// timeout := time.Second * 5
	
	core.Log(certificates, keyword, severity.Low, tlds, matchers)

	// Test with TLD and Matcher that do not match
	certificates = types.Message{
		Domain:  "example.com",
		Domains: []string{"example.com", "www.example.com"},
		Issuer:  "Let's Encrypt",
		Source:  "Google Inc Logs",
		SubjectAltName: "DNS*.example.com, www.example.com",
	}
	keyword = "nubank"
	tlds = []string{"com$"}
	matchers = []string{"invalidmatcher"}

	core.Log(certificates, keyword, severity.Medium, tlds, matchers)

	// Test with TLD and Matcher that match
	certificates = types.Message{
		Domain:   "example.com",
		Domains:  []string{"example.com"},
		Issuer:  "Let's Encrypt",
		Source:  "Google Inc Logs",
		SubjectAltName: "DNS*.nubankdigital, www.nubankdigital.app",
	}
	tlds = []string{"com$"}
	matchers = []string{"Example Domain"}

	core.Log(certificates, keyword, severity.High, tlds, matchers)
}
