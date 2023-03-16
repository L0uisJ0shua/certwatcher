package main

import (
    "net/http"
    "testing"
    "fmt"
    matchers "pkg/matchers"
    "pkg/types"
)

type RequestParams struct {
    Method string
    Paths  []string
}



func TestGet(t *testing.T) {
    testCases := []struct {
        url            string
        paths          []string
        expectedTitle  string
        expectedStatus int
    }{
        {
            url:            "https://orebrosakerhetscenter.se",
            paths:          []string{"/.git/config", "/.git/HEAD"},
            expectedTitle:  "repositoryformatversion",
            expectedStatus: http.StatusOK,
        },
        {
            url:            "https://logbook.billchen.win",
            paths:          []string{"/", "/search?q=golang"},
            expectedTitle:  "Google",
            expectedStatus: http.StatusOK,
        },
    }

    for _, tc := range testCases {

        params := &RequestParams{
            Method: "GET",
            Paths:  tc.paths,
        }

        mParams := &matchers.RequestParams{
            Method: params.Method,
            Paths:  params.Paths,
        }

        doc, statusCode, err := matchers.Get(tc.url, mParams)
        if err != nil {
            t.Errorf("unexpected error: %v", err)
        }

        if statusCode != tc.expectedStatus {
            t.Errorf("unexpected status code for %s: expected %d, got %d", tc.url, tc.expectedStatus, statusCode)
        }

        if doc == nil {
            t.Errorf("expected a non-nil goquery.Document for %s", tc.url)
        } else {
            // verifica se todas as URLs foram chamadas corretamente
            expectedURLs := make(map[string]bool)
            for _, path := range tc.paths {
                expectedURL := fmt.Sprintf("%s%s", tc.url, path)
                expectedURLs[expectedURL] = true
            }
        }
    }
}


func TestMatch(t *testing.T) {
    // Cria um Matcher com valores de exemplo.
    m := &matchers.Matcher{
        Keywords: []string{"example", "test"},
        TLDs:     []string{"com", "net", "org"},
        Matchers: []string{`^http:\/\/`, `^https:\/\/`},
    }

    // Cria uma lista de casos de teste.
    testCases := []struct {
        name     string
        msg      types.Message
        keywords []string
        tlds     []string
        matchers []string
        depth    int
        req      types.Request
        severity string
        expected bool
    }{
        {
            name: "exact match",
            msg: types.Message{
                Domain: "example.com",
            },
            keywords: []string{"example"},
            tlds:     []string{"com"},
            matchers: []string{},
            depth:    1,
            req:      types.Request{},
            severity: "low",
            expected: true,
        },
        {
            name: "no match",
            msg: types.Message{
                Domain: "foo.com",
            },
            keywords: []string{"example"},
            tlds:     []string{"com"},
            matchers: []string{},
            depth:    1,
            req:      types.Request{},
            severity: "low",
            expected: false,
        },
        {
            name: "matcher match",
            msg: types.Message{
                Domain: "https://example.com",
            },
            keywords: []string{},
            tlds:     []string{},
            matchers: []string{`^https:\/\/`},
            depth:    1,
            req:      types.Request{},
            severity: "low",
            expected: true,
        },
        {
            name: "invalid matcher",
            msg: types.Message{
                Domain: "http://example.com",
            },
            keywords: []string{},
            tlds:     []string{},
            matchers: []string{`\`}, // matcher inválido
            depth:    1,
            req:      types.Request{},
            severity: "low",
            expected: false,
        },
    }

    // Percorre cada caso de teste e verifica se o resultado é o esperado
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Chama a função Match() com os parâmetros correspondentes.
            m.Match(tc.msg, tc.keywords, tc.tlds, tc.matchers, tc.depth, tc.req, tc.severity)
            // Exibe o resultado no console.
            fmt.Printf("Test case: %v\n\tExpected: %v\n\t", tc.name, tc.expected)
        })
    }
}



func TestHashTLD(t *testing.T) {
    testCases := []struct {
        domain   string
        tld      string
        expected bool
    }{
        {"www.example.com", "com", true},
        {"www.example.org", "org", true},
        {"www.example.net", "com", false},
        {"www.example.co.uk", "uk", true},
        {"www.example.ca", "com", false},
        {"www.example.org", "com", false},
        {"www.example.com.br", "br", true},
        {"cl.yunketop.com", "com", true},
    }

    for _, tc := range testCases {
        if matchers.HashTLD(tc.domain, tc.tld) != tc.expected {
            t.Errorf("%s should be a %s TLD: expected %v, but got %v", tc.domain, tc.tld, tc.expected, !tc.expected)
        }
    }
}
