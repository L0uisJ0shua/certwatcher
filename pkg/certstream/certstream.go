package certstream

import (
	"encoding/json"
	"pkg/types"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/projectdiscovery/gologger"
)

// CertStream is a structure to handle the connection to the CertStream
type CertStream struct {
	URL string
}

// NewCertStream creates a new CertStream
func NewCertStream() *CertStream {
	return &CertStream{
		URL: "wss://certstream.calidog.io",
	}
}

// GetCertificates retrieves a stream of new certificates from the CertStream
func (c *CertStream) GetCertificates() chan *types.CertStreamEvent {
	certificates := make(chan *types.CertStreamEvent)
	go func() {
		defer close(certificates)

		for {
			conn, _, err := websocket.DefaultDialer.Dial(c.URL, nil)
			if err != nil {
				log.Warning().Msgf("Failed to dial CertStream: %v", err)
				continue
			}

			done := make(chan struct{})

			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						// Do nothing, just keep sending heartbeats.
					case <-done:
						return
					}
				}
			}()

			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					log.Warning().Msgf("Error reading message from CertStream: %v", err)
					break
				}

				var event types.CertStreamEvent
				err = json.Unmarshal(message, &event)
				if err != nil {
					log.Warning().Msgf("Error parsing message from CertStream: %v", err)
					continue
				}

				if event.MessageType == "heartbeat" {
					continue
				}

				certificates <- &event
			}

			conn.Close()
		}
	}()

	return certificates
}
