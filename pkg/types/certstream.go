package types

type CertStreamEvent struct {
    Data struct {
        CertIndex float64 `json:"cert_index"`
        CertLink  string  `json:"cert_link"`
        LeafCert  struct {
            AllDomains   []string `json:"all_domains"`
            Extensions   struct {
                AuthorityInfoAccess string `json:"authorityInfoAccess"`
                BasicConstraints    string `json:"basicConstraints"`
                CertificatePolicies string `json:"certificatePolicies"`
                CPS                 string `json:"CPS"`
                CtlPoisonByte       bool   `json:"ctlPoisonByte"`
                ExtendedKeyUsage    string `json:"extendedKeyUsage"`
                KeyUsage            string `json:"keyUsage"`
                SubjectAltName      string `json:"subjectAltName"`
            } `json:"extensions"`
            Fingerprint string `json:"fingerprint"`
            Issuer      struct {
                C             string `json:"C"`
                CN            string `json:"CN"`
                L             string `json:"L"`
                O             string `json:"O"`
                OU            string `json:"OU"`
                ST            string `json:"ST"`
                Aggregated    string `json:"aggregated"`
                EmailAddress string `json:"emailAddress"`
            } `json:"issuer"`
            NotAfter        float64 `json:"not_after"`
            NotBefore       float64 `json:"not_before"`
            SerialNumber    string  `json:"serial_number"`
            SignatureAlgorithm string  `json:"signature_algorithm"`
            Subject         struct {
                C             string `json:"C"`
                CN            string `json:"CN"`
                L             string `json:"L"`
                O             string `json:"O"`
                OU            string `json:"OU"`
                ST            string `json:"ST"`
                Aggregated    string `json:"aggregated"`
                EmailAddress string `json:"emailAddress"`
            } `json:"subject"`
        } `json:"leaf_cert"`
        Seen       float64 `json:"seen"`
        Source     struct {
            Name string `json:"name"`
            URL  string `json:"url"`
        } `json:"source"`
        UpdateType string `json:"update_type"`
    } `json:"data"`
    MessageType string `json:"message_type"`
}
