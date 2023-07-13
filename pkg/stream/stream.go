package stream

import (
	"fmt"
	"sync"
	"time"

	certstream "pkg/certstream"
	"pkg/core"
	"pkg/matchers"
)

var (
	domainMap    = make(map[string]bool)
	domainMapMux sync.Mutex
)

// Certificates captures certificates from a CertStream, a real-time feed of newly issued SSL/TLS certificates.
// It takes a slice of keywords to check against the domain name of each certificate received and a list of valid TLDs.
func Certificates(t []core.Models, certsPerMinutes int) {

	stream := certstream.NewCertStream()
	certs := 0
	eventsPerMinute := certsPerMinutes
	cacheDuration := 30
	cache := make(map[string]time.Time)
	cacheMutex := sync.Mutex{}

	// Start a goroutine to remove expired cache entries periodically
	go func() {
		for {
			time.Sleep(time.Duration(cacheDuration) * time.Minute)
			cacheMutex.Lock()
			for domain, timestamp := range cache {
				if time.Since(timestamp) > time.Duration(cacheDuration)*time.Minute {
					delete(cache, domain)
				}
			}
			cacheMutex.Unlock()
		}
	}()

	// Obter um canal de eventos do CertStream
	eventChannel := stream.GetCertificates(eventsPerMinute)

	// Create a new spinner and start it in a goroutine
	/*s := spinner.New(spinner.CharSets[14], 10*time.Millisecond)
	s.Color("", "bold")

	go func() {
		s.Start()
		for range time.Tick(5 * time.Second) {
			s.Restart()
			s.Reverse()
		}
	}()

	s.UpdateSpeed(100 * time.Millisecond)*/ // Update the speed the spinner spins at

	// Add a new line after the spinner to avoid overlapping with the next line of output
	fmt.Println()

	// Iterate over each certificate event received from CertStream
	for event := range eventChannel {

		// Update the spinner message with the number of certificates emitted
		// s.Suffix = fmt.Sprintf(" Capturing certificates for analysis %d\n", certs)

		// Extract relevant information from the certificate event
		certificates := matchers.Certificates{
			Domain:         event.Data.LeafCert.Subject.CN,
			AllDomains:     event.Data.LeafCert.AllDomains,
			Issuer:         event.Data.LeafCert.Issuer.O,
			Source:         event.Data.Source.Name,
			SubjectAltName: event.Data.LeafCert.Issuer.Aggregated,
		}

		// Check if the domain is already cached
		cacheMutex.Lock()
		if _, ok := cache[certificates.Domain]; ok {
			cacheMutex.Unlock()
			// log.Info().Msgf("Domain %s is cached\n\n", certificates.Domain)
			continue
		}
		cache[certificates.Domain] = time.Now()
		cacheMutex.Unlock()

		domainMapMux.Lock()
		if domainMap[certificates.Domain] {
			domainMapMux.Unlock()
			continue
		}
		domainMap[certificates.Domain] = true
		domainMapMux.Unlock()

		// Iterate over each template and call matcher.Match for each one
		for _, template := range t {
			// Create a new Matcher object with the desired matching criteria
			matcher := &matchers.Matcher{
				ID:       template.ID,
				Keywords: template.Keywords,
				TLDs:     template.TLDs,
				Tags:     template.Tags,
				Matchers: template.Matchers,
				Requests: matchers.Request{
					Method:    template.Requests.Method,
					Path:      template.Requests.Path,
					Condition: template.Requests.Condition,
				},
				Status:    template.Status,
				Size:      template.Sizes,
				Condition: template.Condition,
				Severity:  template.Severity,
				Author:    template.Author,
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

		// Esperar até o próximo minuto para atender ao limite de eventos por minuto
		time.Sleep(time.Minute / time.Duration(eventsPerMinute))

		// Increment the counter for the number of certificates emitted
		certs++

	}
	// Stop the spinner
	// s.Stop()
}
