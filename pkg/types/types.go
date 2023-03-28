package types

type Message struct {
    Domain         string
    Domains        []string
    Issuer         string
    Source         string
    SubjectAltName string
}

type Protocols struct {
    DNS string
    SSL string
    Log string
}
