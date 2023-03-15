package stream

import (
	"time"
	"github.com/briandowns/spinner"
	log "github.com/projectdiscovery/gologger"
	certstream "pkg/certstream"
	match "pkg/matchers"
	types "pkg/types"
	"fmt"
)

// Function that captures certificates from a CertStream, a real-time feed of newly issued SSL/TLS certificates.
// It takes a slice of keywords to check against the domain name of each certificate received and a list of valid TLDs.
func Certificates(keywords []string, tlds []string, matcher []string, requests types.Request, severity string) {

	// Initializes the variable 'certs' with the value of zero.
	certs := 0

	// Prints an informational message indicating that
	// the code is capturing certificates for analysis.
	log.Info().Msg("Capturing the certificates for analysis\n\n")

	// Create a new spinner
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)

	// Start the spinner in a goroutine
	go func() {
		s.Start()
		for {
			<-time.Tick(60 * time.Second)
			s.Restart()
		}
	}()

	// Capturing certificates from a CertStream, real-time
	// feed of newly issued SSL/TLS certificates.
	stream := certstream.NewCertStream()

	// Iterates over each certificate event received from CertStream.
	for event := range stream.GetCertificates() {

		// Increments the counter for the number of certificates emitted.
		certs++

		// Extracts relevant information from the certificate event.
		certificates := types.Message{
			Domain:         event.Data.LeafCert.Subject.CN,
			Domains:        event.Data.LeafCert.AllDomains,
			Issuer:         event.Data.LeafCert.Issuer.O,
			Source:         event.Data.Source.Name,
			SubjectAltName: event.Data.LeafCert.Issuer.Aggregated,
		}

		// Checks if the certificate domain matches any of the specified keywords.
		template := match.New(keywords, tlds, matcher)
		template.Match(certificates, keywords, tlds, matcher, certs, requests, severity)

		// Update the spinner message with the number of certificates emitted
		logMessage := fmt.Sprintf(" Certificates emitted: %d\n", certs)
		s.Suffix = logMessage
	}
	// Stop the spinner
	s.Stop()
}
