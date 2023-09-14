package certstream

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"pkg/types"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/projectdiscovery/gologger"
)

// CertStream is a structure to handle the connection to the CertStream
type CertStream struct {
	URL               string
	Dialer            *websocket.Dialer
	HandshakeTimeout  time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	PingPeriod        time.Duration
	PongWait          time.Duration
	ReconnectDur      time.Duration
	MaxMessageSize    int64
	EnableCompression bool
}

// NewCertStream creates a new CertStream
func NewCertStream() *CertStream {
	return &CertStream{
		URL: "wss://certstream.calidog.io",
		Dialer: &websocket.Dialer{
			HandshakeTimeout: 30 * time.Second,
			ReadBufferSize:   1024,
			WriteBufferSize:  1024,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		HandshakeTimeout:  30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
		PingPeriod:        20 * time.Second,
		PongWait:          60 * time.Second,
		ReconnectDur:      time.Second,
		MaxMessageSize:    1024 * 1024,
		EnableCompression: true,
	}
}

// GetCertificates retrieves a stream of new certificates from the CertStream
// limitPerMin defines the maximum number of certificates that can be received per minute
func (c *CertStream) GetCertificates(limitPerMin int) chan *types.CertStreamEvent {
	defer func() {
		if err := recover(); err != nil {
			log.Warning().Msgf("panic occurred: %v\n", err)
		}
	}()
	certificates := make(chan *types.CertStreamEvent, limitPerMin)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Warning().Msgf("panic occurred: %v\n", err)
			}
		}()
		defer close(certificates)

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		count := 0

		for {
			if count >= limitPerMin {
				<-ticker.C
				count = 0
			}

			conn, err := c.dialWithTimeout()
			if err != nil {
				log.Warning().Msgf("Failed to dial CertStream: %v", err)
				time.Sleep(c.ReconnectDur)
				continue
			}

			done := make(chan struct{})

			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						err := conn.WriteMessage(websocket.TextMessage, []byte("ping"))
						if err != nil {
							log.Warning().Msgf("Error sending heartbeat to CertStream: %v", err)
							close(done) // Feche o canal 'done' para encerrar a goroutine
							return
						}
					case <-done:
						return
					}
				}
			}()

			for {
				conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))

				_, message, err := conn.ReadMessage()
				if err != nil {
					if errors.Is(err, websocket.ErrCloseSent) {
						// Conexão fechada por nós, não registre um erro.
						return
					}

					log.Warning().Msgf("Error reading message from CertStream: %v", err)
					conn.Close()
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

				select {
				case certificates <- &event:
					count++
				default:
					continue
				}
			}

			close(done) // Feche o canal 'done' após o loop interno
		}
	}()

	return certificates
}

// dialWithTimeout connects to the CertStream with a timeout
func (c *CertStream) dialWithTimeout() (*websocket.Conn, error) {
	dialer := &websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
	}

	conn, _, err := dialer.Dial(c.URL, nil)
	if err != nil {
		return nil, errors.New("No matching body size found in the HTTP request.")
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				conn.WriteMessage(websocket.PingMessage, nil)
			case <-done:
				return
			}
		}
	}()

	conn.SetCloseHandler(func(code int, text string) error {
		return nil
	})

	return conn, nil
}
