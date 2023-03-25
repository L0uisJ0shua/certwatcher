package matchers

import (
    "fmt"
    "net/url"
    "pkg/core"
    "pkg/http"
    "pkg/types"
    "regexp"
    "strings"
    "time"

    log "github.com/projectdiscovery/gologger"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "golang.org/x/net/publicsuffix"
)

type Matcher struct {
    // description: |
    //   Keywords Matcher Contains in Domain Stream
    // values:
    //   - "amazon"
    //   - "google"
    Keywords []string `yaml:"keywords,omitempty" json:"keywords,omitempty" jsonschema:"title=Keywords to match,description=Keywords to match for the response"`
    Matchers []string `yaml:"matchers,omitempty" json:"keywords,omitempty" jsonschema:"title=Keywords to match,description=Keywords to match for the response"`
    // description: |
    //   Tld Matcher Contains in Domain Stream
    // values:
    //   - "com"
    //   - "io"
    TLDs []string `yaml:"tld,omitempty" json:"tld,omitempty" jsonschema:"title=Tlds to match,description=Tlds to match for the response"`
    // description: |
    //   Condition is the optional condition between two matcher variables. By default,
    //   the condition is assumed to be OR.
    // values:
    //   - "and"
    //   - "or"
    Condition string `yaml:"matcher-condition,omitempty" json:"matcher-condition,omitempty" jsonschema:"title=Matcher condition between matcher variables,description=Condition between the matcher variables,enum=and,enum=or"`
    // description: |
    //   Status are the acceptable status codes for the response.
    // examples:
    //   - value: >
    //       []int{200, 302}
    Status []int `yaml:"status,omitempty" json:"status,omitempty" jsonschema:"title=status StatusCode to match,description=Status to match for the response"`
    // description: |
    //   Size is the acceptable size for the response
    // examples:
    //   - value: >
    //       []int{3029, 2042}
    Size []int `yaml:"size,omitempty" json:"size,omitempty" jsonschema:"title=Size to match,description=Size to match for the response"`
    // description: |
    //   Regex contains Regular Expression patterns required to be present in the response part.
    // examples:
    //   - name: Match for Stripe Key via Regex
    //     value: >
    //       []string{`(?i)stripe(.{0,20})?sk_test_[0-9a-zA-Z]{24}`}
    //   - name: Matching APP variables found in response body
    //     value: >
    //       []string{`(?m)^DB_(HOST|PASSWORD|DATABASE)`}
    Pattern []string `yaml:"pattern,omitempty" json:"regex,omitempty" jsonschema:"title=regex to match in response,description=Regex contains regex patterns required to be present in the response part"`
}

func Severity(level string) (severity.Severity, error) {
    switch strings.ToLower(level) {
    case "info":
        return severity.Info, nil
    case "low":
        return severity.Low, nil
    case "medium":
        return severity.Medium, nil
    case "high":
        return severity.High, nil
    default:
        return severity.Unknown, nil
    }
}

func New(keywords, tlds, matchers []string) *Matcher {
    return &Matcher{
        Keywords: keywords,
        TLDs:     tlds,
        Matchers: matchers,
    }
}

func parseDomain(domain string) (string, error) {
    u, err := url.Parse(fmt.Sprintf("https://%s", domain))
    if err != nil {
        return "", err
    }
    domain, err = publicsuffix.EffectiveTLDPlusOne(u.Hostname())
    if err != nil {
        return "", err
    }
    return domain, nil
}

func (m *Matcher) Match(certificates types.Message, certs int, statusCode []int, sizesCodes []int, requests types.Request, level string, templateID string) {

    go func() {

        // Inicializa a variável patterns com o valor 0.
        patterns := 0

        domain, err := parseDomain(certificates.Domain)
        if err != nil {
            log.Debug().Msg("Error parsing domain")
            return
        }

        // Monta a URL para a requisição.
        url := fmt.Sprintf("https://%s", domain)

        level, _ := Severity(level)

        var catcher string
        // Verifica se a resposta já está em cache.
        params := &http.Request{
            Method: requests.Method,
            Paths:  requests.Path,
        }

        // Se a resposta não estiver em cache, faz a requisição HTTP.
        doc, responseStatusCode, responseSizesCode, err := http.Requests(url, params)

        if err != nil {
            return
        }

        status, matchStatusCode := m.MatchStatusCodes(responseStatusCode, statusCode)

        // Verifica se há correspondência com os matchers utilizando expressões regulares.
        for _, matcher := range m.Matchers {

            re, err := regexp.Compile(matcher)
            if err != nil {
                break
            }

            if re.MatchString(doc.Text()) {
                catcher = matcher
                break
            }
        }

        // Verifica se o domínio do objeto certificates termina com algum TLD.
        tld, matchTLD := m.MatchTLD(domain, m.TLDs)

        if matchTLD {
            patterns++
        }

        keywords, matchKeyword := m.MatchKeywords(domain, m.Keywords)

        if matchKeyword {
            patterns++
        }

        keyword := strings.Join(keywords, ", ")

        var levels severity.Severity
        switch {
        case patterns >= 3:
            levels = severity.High
        case patterns >= 1:
            levels = severity.Medium
        default:
            levels = severity.Low
        }

        if matchStatusCode {
            log.Debug().Str("requests", fmt.Sprintf("%v", domain)).Str("status", fmt.Sprintf("%d", status)).Str("sizes", fmt.Sprintf("%d", responseSizesCode)).Msg("HTTP Request Returned Match Size Code")
        }

        switch {
        case len(keyword) > 0:
            log.Info().Msgf("Suspicious activity found at %s\n", time.Now().Format("01-02-2006 15:04:05"))
            log.Info().Msgf("Number of certificates issued: %d\n", certs)
            log.Info().Msgf("Domain Keyword Match (%s)", keyword)
            if len(catcher) > 0 {
                log.Info().Msgf("Matching regular expression found: %s", catcher)
                core.LogCertificates(certificates, keyword, severity.High, m.TLDs, m.Matchers)
                return
            }
            if matchTLD {
                log.Info().Msgf("Domain matched TLDs (Top-Level Domains) %s", tld)
            }
            core.LogCertificates(certificates, keyword, levels, m.TLDs, m.Matchers)
        default:
            if len(catcher) > 0 {
                log.Info().Msgf("Pattern successfully found %s\n", time.Now().Format("01-02-2006 15:04:05"))
                log.Info().Msgf("Number of certificates issued: %d\n", certs)
                log.Info().Msgf("Matching regular expression found: %s\n", catcher)
                core.Log(templateID, "http", level, domain, strings.Split(catcher, " "))
                core.LogCertificates(certificates, keyword, level, m.TLDs, m.Matchers)
                return
            }
        }

    }()
}
