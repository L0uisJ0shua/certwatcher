package types

import "github.com/projectdiscovery/goflags"

type Message struct {
    Domain       string
    Domains      []string
    Issuer         string
    Source         string
    SubjectAltName string
}

type Protocols struct {
    DNS         string
    SSL         string
    Log         string
}

type Options struct {
    Templates      goflags.StringSlice
    Validate       bool
    Headless       bool
    PageTimeout    int
    PageScreenShot bool
    Verbose        bool
    Debug          bool
    Version        bool
    Retries        int
    Timeout        int
}

func DefaultOptions() *Options {
    return &Options{
        Timeout: 5,
        Retries: 1,
    }
}
