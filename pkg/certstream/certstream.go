package certstream

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	log "github.com/projectdiscovery/gologger"
	"pkg/types"
	"time"
)

// CertStreamEvent represents a single event from the CertStream
type CertStreamEvent = types.CertStreamEvent

// CertStream is a structure to handle the connection to the CertStream
type CertStream struct {
	URL string
}

const (
	period time.Duration = 15 * time.Second
)

// NewCertStream creates a new CertStream
func NewCertStream() *CertStream {
	return &CertStream{
		URL: "wss://certstream.calidog.io",
	}
}

// GetCertificates retrieves a stream of new certificates from the CertStream
func (c *CertStream) GetCertificates() chan *CertStreamEvent {
	certificates := make(chan *CertStreamEvent)
	go func() {

		defer close(certificates)

		for {
			conn, _, err := websocket.DefaultDialer.Dial(c.URL, nil)
			if err != nil {
				time.Sleep(5 * time.Second)
				log.Debug().Msgf("Error dialing certstream: %d", err)
				continue
			}
			defer conn.Close()

				done := make(chan struct{})

			go func() {
				ticker := time.NewTicker(period)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						log.Debug().Msgf("Error dialing certstream: %d", websocket.PingMessage)
					case <-done:
						return
					}
				}
			}()

			for {
				conn.SetReadDeadline(time.Now().Add(15 * time.Second))
				_, message, err := conn.ReadMessage()
				if err != nil {
					log.Debug().Msgf("Error reading message from certstream %s", err)
					break
				}

				var event CertStreamEvent
				err = json.Unmarshal(message, &event)
				if err != nil {
					log.Debug().Msgf("Error Unmarshal message from certstream %s", err)
					continue
				}

				if event.MessageType == "heartbeat" {
					continue
				}

				certificates <- &event
			}
		}
	}()
	return certificates
}
