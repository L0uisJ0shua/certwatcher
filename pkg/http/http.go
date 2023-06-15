package http

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	browser "github.com/EDDYCJY/fake-useragent"
	"github.com/gocolly/colly/v2"
	log "github.com/projectdiscovery/gologger"
)

type RequestMethod string

const (
	GET  RequestMethod = "GET"
	POST RequestMethod = "POST"
	HEAD RequestMethod = "HEAD"
)

type Request struct {
	Paths     []string      `yaml:"path,omitempty" json:"path,omitempty" jsonschema:"title=paths,description=String paths that represent the URL paths"`
	Method    RequestMethod `yaml:"method,omitempty" json:"method,omitempty" jsonschema:"title=String that specifies the HTTP request description=the default method ("GET") will be used."`
	Condition string        `yaml:"condition,omitempty" json:"condition,omitempty" jsonschema:"title=Condition of response to match,description=String that specifies a condition to match against the response"`
	Body      string        `yaml:"body,omitempty" json:"body,omitempty" jsonschema:"title=String that represents the body of the HTTP request"`
}

var UserAgent = browser.Random()

func Requests(url string, req *Request) (*colly.Response, []int, []int, error) {
	var (
		status    []int
		sizes     []int
		resp      *colly.Response
		responses = make(chan *colly.Response, len(req.Paths))
	)

	c := colly.NewCollector(
		colly.DisallowedDomains("example.com"),
	)

	Timeout := 60 * time.Second
	c.SetRequestTimeout(Timeout)

	c.OnRequest(func(r *colly.Request) {
		method := strings.ToUpper(string(req.Method))
		switch method {
		case string(POST):
			r.Method = "POST"
			setRequestBody(r, req.Body)
		case string(HEAD):
			r.Method = "HEAD"
		default:
			r.Method = "GET"
		}
	})

	c.OnResponse(func(r *colly.Response) {
		status = append(status, r.StatusCode)
		sizes = append(sizes, len(r.Body))
		responses <- r
	})

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
		return nil, nil, nil, err
	}

	log.Debug().Msgf("Sending %s request: %s", req.Method, resp.Request.URL)

	return resp, status, sizes, nil
}

func setRequestBody(r *colly.Request, body string) {
	if body != "" {
		r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Body = ioutil.NopCloser(strings.NewReader(body))
	}
}

func Get(url string, paths []string) (*colly.Response, []int, []int, error) {
	req := &Request{
		Paths:  paths,
		Method: GET,
	}

	return Requests(url, req)
}

func Post(url string, paths []string, body string) (*colly.Response, []int, []int, error) {
	req := &Request{
		Paths:  paths,
		Method: POST,
		Body:   body,
	}

	return Requests(url, req)
}

func Head(url string, paths []string) (*colly.Response, []int, []int, error) {
	req := &Request{
		Paths:  paths,
		Method: GET,
	}

	return Requests(url, req)
}
