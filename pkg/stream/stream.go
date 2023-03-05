package stream

import (
	log "github.com/projectdiscovery/gologger"
	certstream "pkg/certstream"
	match "pkg/matchers"
	types "pkg/types"
)
// Function that captures certificates from a CertStream, a real-time feed of newly issued SSL/TLS certificates.
// It takes a slice of keywords to check against the domain name of each certificate received and a list of valid TLDs.
func Certificates(keywords []string, tlds []string, matcher []string) {

	// Initializes the variable 'certs' with the value of zero.
	certs := 0

	// Prints an informational message indicating that 
	// the code is capturing certificates for analysis.
	log.Info().Msg("Capturing the certificates for analysis\n\n")

	// Capturing certificates from a CertStream, real-time 
	// feed of newly issued SSL/TLS certificates.
	stream := certstream.NewCertStream()

	// Iterates over each certificate event received from CertStream.
	for event := range stream.GetCertificates() { 

		// Extracts relevant information from the certificate event.
		certificates := types.Message{
			Domain:         event.Data.LeafCert.Subject.CN,
			Domains:        event.Data.LeafCert.AllDomains,
			Issuer:         event.Data.LeafCert.Issuer.O,
			Source:         event.Data.Source.Name,
			SubjectAltName: event.Data.LeafCert.Extensions.SubjectAltName,
		}
		
		// Checks if the certificate domain matches any of the specified keywords.
		template := match.New(keywords, tlds, matcher)
		template.Match(certificates, keywords, tlds, matcher, certs)
		// Increments the counter for the number of certificates processed.
		certs++
	}
}
