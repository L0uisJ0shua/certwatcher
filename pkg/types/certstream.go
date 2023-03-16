package types

type CertStreamEvent struct {
    Data        CertStreamData  `json:"data"`
    MessageType string          `json:"message_type"`
}

type CertStreamData struct {
    CertIndex  float64         `json:"cert_index"`
    CertLink   string          `json:"cert_link"`
    LeafCert   LeafCertificate `json:"leaf_cert"`
    Seen       float64         `json:"seen"`
    Source     CertSource      `json:"source"`
    UpdateType string          `json:"update_type"`
}

type LeafCertificate struct {
    AllDomains         []string        `json:"all_domains"`
    Extensions         CertExtensions  `json:"extensions"`
    Fingerprint        string          `json:"fingerprint"`
    Issuer             CertIssuer      `json:"issuer"`
    NotAfter           float64         `json:"not_after"`
    NotBefore          float64         `json:"not_before"`
    SerialNumber       string          `json:"serial_number"`
    SignatureAlgorithm string          `json:"signature_algorithm"`
    Subject            CertSubject     `json:"subject"`
}

type CertExtensions struct {
    AuthorityInfoAccess string `json:"authorityInfoAccess"`
    BasicConstraints    string `json:"basicConstraints"`
    CertificatePolicies string `json:"certificatePolicies"`
    CPS                 string `json:"CPS"`
    CtlPoisonByte       bool   `json:"ctlPoisonByte"`
    ExtendedKeyUsage    string `json:"extendedKeyUsage"`
    KeyUsage            string `json:"keyUsage"`
    SubjectAltName      string `json:"subjectAltName"`
}

type CertIssuer struct {
    C             string `json:"C"`
    CN            string `json:"CN"`
    L             string `json:"L"`
    O             string `json:"O"`
    OU            string `json:"OU"`
    ST            string `json:"ST"`
    Aggregated    string `json:"aggregated"`
    EmailAddress string `json:"emailAddress"`
}

type CertSubject struct {
    C             string `json:"C"`
    CN            string `json:"CN"`
    L             string `json:"L"`
    O             string `json:"O"`
    OU            string `json:"OU"`
    ST            string `json:"ST"`
    Aggregated    string `json:"aggregated"`
    EmailAddress string `json:"emailAddress"`
}

type CertSource struct {
    Name string `json:"name"`
    URL  string `json:"url"`
}
