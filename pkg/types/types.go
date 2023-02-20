package types

import "github.com/projectdiscovery/goflags"


const (
    SSLDNSNames string = "ssl-dns-names"
    DNS         string = "dns"
    CAAIssuer   string = "caa-issuer"
    SSL         string = "ssl"
    Keyword     string = "keyword"
)

type Options struct {
    Templates      goflags.StringSlice
    Keywords       goflags.StringSlice
    Validate       bool
    Headless       bool
    PageTimeout    int
    PageScreenShot bool
    Verbose        bool
    VerboseVerbose bool
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
