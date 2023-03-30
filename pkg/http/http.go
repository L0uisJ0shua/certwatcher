package http

import (
	"fmt"
	"strings"
	"time"

	browser "github.com/EDDYCJY/fake-useragent"
	"github.com/gocolly/colly/v2"
	log "github.com/projectdiscovery/gologger"
)

type Request struct {
	Paths     []string `yaml:"path,omitempty" json:"path,omitempty" jsonschema:"title=paths,description=String paths that represent the URL paths"`
	Method    string   `yaml:"method,omitempty" json:"method,omitempty" jsonschema:"title=String that specifies the HTTP request description=the default method ("GET") will be used."`
	Condition string   `yaml:"condition,omitempty" json:"condition,omitempty" jsonschema:"title=Condition of response to match,description=String that specifies a condition to match against the response"`
}

const (
	Timeout = 30 * time.Second
)

var UserAgent = browser.Random()

func Requests(url string, req *Request) (*colly.Response, []int, []int, error) {

	var (
		status    []int
		sizes     []int
		resp      *colly.Response
		responses = make(chan *colly.Response, len(req.Paths))
		UserAgent = UserAgent
	)

	c := colly.NewCollector(
		colly.Async(true),
		colly.DisallowedDomains("example.com"),
	)

	c.SetRequestTimeout(Timeout)

	// Set Random Fake User Agent
	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("User-Agent", UserAgent)
		method := strings.ToUpper(req.Method)
		switch method {
		case "POST":
			r.Method = "POST"
		case "HEAD":
			r.Method = "HEAD"
		default:
			r.Method = "GET"
		}
		// log.Debug().Msgf("Sending %s request: %s", r.Method, r.URL)
	})

	c.OnResponse(func(r *colly.Response) {
		status = append(status, r.StatusCode)
		sizes = append(sizes, len(r.Body))
		responses <- r
		log.Debug().
			Str("domain", fmt.Sprintf("%s", r.Request.URL)).
			Str("status", fmt.Sprintf("%d", r.StatusCode)).
			Msg("Received response from")
	})

	if len(req.Paths) == 0 {
		req.Paths = []string{"/"}
		log.Debug().
			Str("path", fmt.Sprintf("%s", req.Paths[0])).
			Msg("Request paths not provided, using default path")
	}

	for _, path := range req.Paths {
		c.Visit(fmt.Sprintf("%s%s", url, path))
	}

	go func() {
		c.Wait()
		close(responses)
	}()

	for response := range responses {
		if response == nil {
			continue
		}
		resp = response
	}

	if len(status) == 0 {
		err := fmt.Errorf("no response received")
		// log.Debug().Msgf("Error: %v", err)
		return nil, nil, nil, err
	}

	// log.Debug().Msgf("Returning response from: %s with status code: %d and body size: %d", resp.Request.URL, resp.StatusCode, len(resp.Body))
	log.Debug().
		Str("domain", fmt.Sprintf("%s", resp.Request.URL)).
		Str("status", fmt.Sprintf("%d", resp.StatusCode)).
		Str("size", fmt.Sprintf("%d", len(resp.Body))).
		Msg("Returning response from with")
	return resp, status, sizes, nil
}
