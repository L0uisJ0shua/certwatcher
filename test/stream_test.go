package main

import (
	"testing"
	"pkg/core"
	"pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)


func Log(t *testing.T) {

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
	
	core.Log(certificates, keyword, severity.High, tlds, matchers)
}
