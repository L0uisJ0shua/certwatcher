package certstream

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// CertStreamEvent represents a single event from the CertStream
type CertStreamEvent struct {
	MessageType string `json:"message_type"`
	Data        struct {
		LeafCert struct {
			Subject struct {
				Domain string `json:"CN"`
			} `json:"subject"`
			Extensions struct {
				CertificatePolicies string `json:"certificatePolicies"`
			} `json:"extensions"`
			ExpiresAt int64 `json:"not_before"`
			CreatedAt int64 `json:"not_after"`
		} `json:"leaf_cert"`
		Source struct {
			Url  string `json:"url"`
			Name string `json:"name"`
		} `json:"source"`
	} `json:"data"`
}

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
func (c *CertStream) GetCertificates() chan *CertStreamEvent {
	certificates := make(chan *CertStreamEvent)
	go func() {
		defer close(certificates)
		for {
			conn, _, err := websocket.DefaultDialer.Dial(c.URL, nil)
			if err != nil {
				log.Debug("Error dialing certstream:", err)
				continue
			}
			defer conn.Close()

			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					log.Debug("Error reading message from certstream")
					break
				}

				var event CertStreamEvent
				err = json.Unmarshal(message, &event)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err,
					}).Error("Error unmarshalling message from certstream")
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
