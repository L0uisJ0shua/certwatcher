package stream

import (
	"fmt"
	"time"

	"github.com/briandowns/spinner"

	certstream "pkg/certstream"
	"pkg/core"
	"pkg/matchers"
)

type Message struct {
	Domain         string
	Domains        []string
	Issuer         string
	Source         string
	SubjectAltName string
}

// Certificates captures certificates from a CertStream, a real-time feed of newly issued SSL/TLS certificates.
// It takes a slice of keywords to check against the domain name of each certificate received and a list of valid TLDs.
func Certificates(t []core.Models) {

	// Create a new CertStream to capture certificates in real-time
	stream := certstream.NewCertStream()

	// Initialize a counter for the number of certificates emitted
	certs := 0

	// Create a new spinner and start it in a goroutine
	s := spinner.New(spinner.CharSets[14], 60*time.Millisecond)

	s.Color("whites", "bold")

	go func() {
		s.Start()
		for range time.Tick(60 * time.Second) {
			s.Restart()
			s.Reverse()
		}
	}()

	s.UpdateSpeed(60 * time.Millisecond) // Update the speed the spinner spins at

	// Iterate over each certificate event received from CertStream
	for event := range stream.GetCertificates() {
		// Increment the counter for the number of certificates emitted
		certs++

		// Update the spinner message with the number of certificates emitted
		s.Suffix = fmt.Sprintf(" Capturing certificates for analysis %d\n", certs)

		// Extract relevant information from the certificate event
		certificates := matchers.Certificates{
			Domain:         event.Data.LeafCert.Subject.CN,
			AllDomains:     event.Data.LeafCert.AllDomains,
			Issuer:         event.Data.LeafCert.Issuer.O,
			Source:         event.Data.Source.Name,
			SubjectAltName: event.Data.LeafCert.Issuer.Aggregated,
		}

		// Iterate over each template and call matcher.Match for each one
		for _, template := range t {
			// Create a new Matcher object with the desired matching criteria

			requests := matchers.Request{
				Method:    template.Requests.Method,
				Path:      template.Requests.Path,
				Condition: template.Requests.Condition,
			}

			matcher := &matchers.Matcher{
				ID:        template.ID,
				Keywords:  template.Keywords,
				TLDs:      template.TLDs,
				Tags:      template.Tags,
				Matchers:  template.Matchers,
				Requests:  requests,
				Status:    template.Status,
				Size:      template.Sizes,
				Condition: template.Condition,
				Severity:  template.Severity,
				MatchAll:  true,
			}

			capacity := 1
			sem := make(chan struct{}, capacity) // cria um semáforo com capacidade para 10 goroutines
			for i := 0; i < capacity; i++ {
				sem <- struct{}{} // adquire uma posição no semáforo, bloqueando se não houver posições disponíveis
				go func() {
					defer func() { <-sem }()           // libera uma posição no semáforo ao final da execução da goroutine
					matcher.Match(certificates, certs) // processa os certificados
				}()
			}
		}
	}
	// Stop the spinner
	s.Stop()
}
