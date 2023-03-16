package stream

import (
	"fmt"
	"time"

	"github.com/briandowns/spinner"
	log "github.com/projectdiscovery/gologger"

	certstream "pkg/certstream"
	match "pkg/matchers"
	types "pkg/types"
)

// Certificates captures certificates from a CertStream, a real-time feed of newly issued SSL/TLS certificates.
// It takes a slice of keywords to check against the domain name of each certificate received and a list of valid TLDs.
func Certificates(keywords []string, tlds []string, matcher []string, requests types.Request, severity string) {
	// Create a new spinner and start it in a goroutine
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	go func() {
		s.Start()
		for range time.Tick(5 * time.Second) {
			s.Restart()
		}
	}()

	// Create a new CertStream to capture certificates in real-time
	stream := certstream.NewCertStream()

	// Initialize a counter for the number of certificates emitted
	certs := 0

	// Print an informational message indicating that the code is capturing certificates for analysis
	log.Info().Msg("Capturing certificates for analysis...\n\n")

	// Iterate over each certificate event received from CertStream
	for event := range stream.GetCertificates() {
		// Increment the counter for the number of certificates emitted
		certs++

		// Extract relevant information from the certificate event
		certificates := types.Message{
			Domain:         event.Data.LeafCert.Subject.CN,
			Domains:        event.Data.LeafCert.AllDomains,
			Issuer:         event.Data.LeafCert.Issuer.O,
			Source:         event.Data.Source.Name,
			SubjectAltName: event.Data.LeafCert.Issuer.Aggregated,
		}

		// Check if the certificate domain matches any of the specified keywords
		template := match.New(keywords, tlds, matcher)
		template.Match(certificates, keywords, tlds, matcher, certs, requests, severity)

		// Update the spinner message with the number of certificates emitted
		logMessage := fmt.Sprintf(" Certificates emitted: %d\n ", certs)
		s.Suffix = logMessage
	}

	// Stop the spinner
	s.Stop()
}
