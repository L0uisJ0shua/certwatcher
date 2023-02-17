package types

type CertStreamEvent struct {
    MessageType string `json:"message_type"`
    Data        struct {
        UpdateType string `json:"update_type"`
        LeafCert   struct {
            Subject struct {
                Aggregated string `json:"aggregated"`
                C          string `json:"C"`
                ST         string `json:"ST"`
                L          string `json:"L"`
                O          string `json:"O"`
                OU         string `json:"OU"`
                CN         string `json:"CN"`
            } `json:"subject"`
            Extensions struct {
                KeyUsage              string `json:"keyUsage"`
                ExtendedKeyUsage      string `json:"extendedKeyUsage"`
                BasicConstraints      string `json:"basicConstraints"`
                SubjectKeyIdentifier  string `json:"subjectKeyIdentifier"`
                AuthorityKeyIdentifier string `json:"authorityKeyIdentifier"`
                AuthorityInfoAccess   string `json:"authorityInfoAccess"`
                SubjectAltName        string `json:"subjectAltName"`
                CertificatePolicies   string `json:"certificatePolicies"`
            } `json:"extensions"`
            NotBefore    float64 `json:"not_before"`
            NotAfter     float64 `json:"not_after"`
            SerialNumber string  `json:"serial_number"`
            Fingerprint  string  `json:"fingerprint"`
            AsDer        string  `json:"as_der"`
        } `json:"leaf_cert"`
        Chain []struct {
            Subject struct {
                Aggregated string `json:"aggregated"`
                C          string `json:"C"`
                ST         string `json:"ST"`
                L          string `json:"L"`
                O          string `json:"O"`
                OU         string `json:"OU"`
                CN         string `json:"CN"`
            } `json:"subject"`
        } `json:"chain"`
        Source   struct {
            url             string `json:"url"`
            source          string `json:"source"`
            } `json:"source"`
    } `json:"data"`
}