package main

import (
    "testing"
    "github.com/stretchr/testify/assert"
    matchers "pkg/matchers"
    "fmt"
    "pkg/types"
)


type RequestParams struct {
    Method string
    Paths  []string
}

func TestGet(t *testing.T) {

    // Monta a URL para a requisição.
    url := fmt.Sprintf("https://%s", "cl.yunketop.com")

    //Testando com caminho definido no RequestParams
    params := &RequestParams{
        Method: types.Requests.Method,
        Paths:  types.Requests.Path,
    }
    // Se a resposta não estiver em cache, faz a requisição HTTP.
    doc, _, err := matchers.Get(url, params)

    if err != nil {
        return
    }

    assert.NoError(t, err)
    assert.NotNil(t, doc)
}

func TestHashTLD(t *testing.T) {
    testCases := []struct {
        domain string
        tld string
        expected bool
    }{
        {"www.example.com", "com", true},
        {"www.example.org", "org", true},
        {"www.example.net", "com", false},
        {"www.example.co.uk", "uk", true},
        {"www.example.ca", "com", false},
        {"www.example.org", "com", false},
        {"www.example.com.br", "br", true},
        {"cl.yunketop.com", "com", false},
    }

    for _, tc := range testCases {
        if matchers.HashTLD(tc.domain, tc.tld) != tc.expected {
            t.Errorf("%s should be a %s TLD: expected %v, but got %v", tc.domain, tc.tld, tc.expected, !tc.expected)
        }
    }
}

