package http

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type Request struct {
	Paths  []string
	Method string
}

type response struct {
	doc        *goquery.Document
	statusCode int
	size       int
	err        error
}

type getResult struct {
	doc        *goquery.Document
	statusCode int
	err        error
}

func newHTTPConfig() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
	}
}

func newHTTPRequest(method string, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func Paths(req *Request) []string {
	paths := make([]string, 0)
	if len(req.Paths) == 0 {
		paths = append(paths, "/")
	}
	paths = append(paths, req.Paths...)
	return paths
}

func Requests(url string, req *Request) (*goquery.Document, []int, []int, error) {
	client := newHTTPConfig()

	paths := Paths(req)

	var wg sync.WaitGroup
	wg.Add(len(paths))

	requests := make([]string, len(paths))
	statusCodes := make([]int, len(paths))
	sizeCodes := make([]int, 0)

	responses := make(chan response, len(paths))

	for i, path := range paths {
		requests[i] = url + path

		go func(path string) {
			defer wg.Done()

			req, err := newHTTPRequest(req.Method, url+path)
			if err != nil {
				responses <- response{err: err}
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				responses <- response{err: err}
				return
			}

			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				responses <- response{err: err}
			}

			doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
			if err != nil {
				responses <- response{err: err}
			}

			statusCodes = append(statusCodes, resp.StatusCode)
			sizeCodes = append(sizeCodes, len(body))

			responses <- response{doc: doc}
		}(path)
	}

	go func() {
		wg.Wait()
		close(responses)
	}()

	var doc *goquery.Document
	var err error
	for res := range responses {
		if res.err != nil {
			err = res.err
			continue
		}

		doc = res.doc

		if doc != nil {
			continue
		}
	}

	return doc, statusCodes, sizeCodes, err
}
