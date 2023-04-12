package matchers

import (
    "fmt"
    "strings"
    "time"

    "pkg/utils"

    "pkg/http"
    "pkg/templates"

    log "github.com/projectdiscovery/gologger"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "github.com/weppos/publicsuffix-go/publicsuffix"
)

type Matcher struct {
    ID   string   `yaml:"id,omitempty" json:"part,omitempty" jsonschema:"title=Template identify,description=Matches when a template successfully matches a regex"`
    Tags []string `yaml:"tags,omitempty" json:"tags,omitempty" jsonschema:"title=Tags templates,description=Tags corresponding to the loaded template"`

    Severity string `yaml:"severity,omitempty" json:"part,omitempty" jsonschema:"title=seveirty loaded template,description=Severity of the loaded template"`
    //   Part is the part of the request response to match data from.
    //   Each protocol exposes a lot of different parts which are well
    //   documented in docs for each request type.
    // examples:
    //   - value: "\"body\""
    //   - value: "\"raw\""
    Type string `yaml:"type,omitempty" json:"part,omitempty" jsonschema:"title=Match Types,description=Match type body or header"`
    // description: |
    //   Keywords Matcher Contains in Domain Stream
    // values:
    //   - "amazon"
    //   - "google"
    Keywords []string `yaml:"keywords,omitempty" json:"keywords,omitempty" jsonschema:"title=Keywords to match,description=Keywords to match for the domain"`
    // description: |
    //   Matchers Contains in Body Requests
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
    Matchers []string `yaml:"matchers,omitempty" json:"matchers,omitempty" jsonschema:"title=matchers to match in response,description=Matchers contains regex patterns required to be present in the response part"`
    // description: |
    //   MatchAll enables matching for all matcher values. Default is false.
    // values:
    //   - false
    //   - true
    MatchAll bool `yaml:"match,omitempty" json:"match,omitempty" jsonschema:"title=match all values,description=match all matcher values ignoring condition"`
    // description: |
    //   Requests to send over domains matching. Default is "/".
    // values:
    //   - "/"
    //   - "/.git/config"
    condition ConditionType
    Requests  Request `yaml:"requests"`
}

type Request struct {
    Method      string   `yaml:"method"`
    Path        []string `yaml:"path"`
    Description string   `yaml:"description,omitempty"`
    Condition   string   `yaml:"condition,omitempty"`
}

type Certificates struct {
    Domain         string
    AllDomains     []string
    Issuer         string
    Source         string
    SubjectAltName string
}

type Domain struct {
    TLD       string
    Domain    string
    Subdomain string
}

type ConditionType string

const (
    ANDCondition ConditionType = "and"
    ORCondition  ConditionType = "or"
)

type Result struct {
    Size     int
    Status   int
    Keywords []string
    TLDs     bool
    Regexes  []string
    Valid    bool
}

// ConditionTypes is a table for conversion of condition type from string.
var ConditionTypes = map[string]ConditionType{
    "and": ANDCondition,
    "or":  ORCondition,
}

func (c *Certificates) Url() (string, error) {
    domain, err := publicsuffix.Domain(c.Domain)
    if err != nil {
        return "", err
    }
    c.Domain = domain

    return c.Domain, nil
}

func (c *Certificates) Parse() (*Domain, error) {
    domain, err := publicsuffix.Parse(c.Domain)
    if err != nil {
        return nil, err
    }

    return &Domain{
        TLD:       domain.TLD,
        Domain:    domain.SLD,
        Subdomain: domain.TRD,
    }, nil
}

func (r *Result) Validate() *Result {

    valid := true

    // Retorna um novo Result com o valor booleano da validação e os valores correspondentes
    return &Result{
        Size:     r.Size,
        Status:   r.Status,
        Keywords: r.Keywords,
        TLDs:     r.TLDs,
        Regexes:  r.Regexes,
        Valid:    valid,
    }
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

func (m *Matcher) Match(certs Certificates, count int) {
    // Aqui podemos fazer a lógica de match do certificado com base nos critérios do Matcher
    // Neste exemplo, apenas imprimimos alguns campos do certificado e os critérios de match

    baseURL, err := certs.Url() // extract the domain base example -> example.com

    if err != nil {
        return
    }

    for _, domains := range certs.AllDomains {

        result := &Result{}
        url := utils.RemoveWildcardPrefix(domains)

        result.Keywords, _ = m.MatchKeywords(url)
        result.TLDs, _ = m.MatchTLD(url)

        req := &http.Request{
            Method: m.Requests.Method,
            Paths:  m.Requests.Path,
        }

        url = fmt.Sprintf("https://%s", url)
        resp, stats, sizes, err := http.Requests(url, req)

        if err != nil {
            // log.Warning().Msgf("Error making HTTP request: %v", err)
            return
        }

        for _, status := range stats {
            if match, _ := m.MatchStatusCode(status); match {
                result.Status = status
                // log.Debug().
                //     Str("domain", url).
                //     Str("status", fmt.Sprintf("%d", status)).
                //     Msg("Matching status code found in the HTTP request")
            }
        }

        for _, size := range sizes {
            if match, _ := m.MatchSize(size); match {
                result.Size = size
                // log.Debug().
                //     Str("domain", url).
                //     Str("size", fmt.Sprintf("%d", size)).
                //     Msg("Matching body size found in the HTTP request.")
            }
        }

        matched, matches, err := m.MatchRegex(string(resp.Body))

        if matched {
            result.Regexes = matches
            // log.Debug().
            //     Str("domain", url).
            //     Str("matches", fmt.Sprintf("%s", matches)).
            //     Msg("Matching regex found in the HTTP response.")
        }
        // else if err != nil {
        //     log.Debug().Msgf("%v", err)
        // }

        // Chama a função Validate para validar o objeto Result
        validate := result.Validate()

        if !validate.Valid {
            log.Error().Msgf("Domain %s is invalid\n\n", url)
            continue
        }

        level, _ := Severity(m.Severity)

        var (
            keywords = utils.Unique(validate.Keywords)
            tlds     = validate.TLDs
            regex    = utils.Unique(validate.Regexes)
        )

        switch {
        case len(keywords) > 0:
            log.Info().Msgf("Domain %s Matches Keywords (%s)\n", url, strings.Join(keywords, ","))
            log.Info().Msgf("Number of certificates issued: %d", count)
            // Add a new line after the spinner to avoid overlapping with the next line of output
            fmt.Println()

            // Display matched keywords
            for _, keyword := range keywords {
                log.Info().Msgf("Matched keyword: %s", keyword)
            }
        case tlds:
            log.Info().Msgf("Domain %s Matched TLDs (Top-Level Domains)\n", url)
            log.Info().Msgf("Number of certificates issued: %d", count)
            // Add a new line after the spinner to avoid overlapping with the next line of output
            fmt.Println()
        case len(regex) > 0:

            log.Info().Msgf("Pattern successfully at %s", time.Now().Format("01-02-2006 15:04:05"))
            log.Info().Msgf("Number of certificates issued: %d", count)

            certLogs := templates.LogEntryGroup{
                Template: templates.LogEntry{
                    ID:       m.ID,
                    Name:     templates.Protocolos.HTTP,
                    Severity: level,
                    Tags:     utils.Unique(m.Tags),
                    Domain:   url,
                    Options:  []string{"tags"},
                    // Adicionar outras entradas de informação de modelo aqui...
                },
                CertsLog: []templates.LogEntry{
                    {
                        Name:    "ssl-dns-names",
                        Types:   templates.Protocolos.DNS,
                        Domain:  baseURL,
                        Message: strings.Join(certs.AllDomains, ", "),
                    },

                    {
                        Name:    "ssl-issuer",
                        Types:   templates.Protocolos.SSL,
                        Domain:  baseURL,
                        Message: certs.Issuer,
                    },
                    {
                        Name:    "source",
                        Types:   templates.Protocolos.Log,
                        Domain:  baseURL,
                        Message: certs.Source,
                    },
                },
            }
            templates.Log(certLogs)
            // Add a new line after the spinner to avoid overlapping with the next line of output
            fmt.Println()
        default:
            if !validate.Valid {
                log.Error().Msgf("Domain %s is invalid\n\n", url)
            }
        }
    }
}
