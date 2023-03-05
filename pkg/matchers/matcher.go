package matchers

import (
    "fmt"
    "net/http"
    "regexp"
    "strings"
    "time"
    "github.com/PuerkitoBio/goquery"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "pkg/core"
    "pkg/types"
    log "github.com/projectdiscovery/gologger"
    "github.com/patrickmn/go-cache"
    "bytes"
    "io/ioutil"

)

type Matcher struct {
    Keywords []string
    TLDs     []string
    Matchers []string
}

func hasTLD(domain string, tld string) bool {
    re := regexp.MustCompile(fmt.Sprintf(`\.[a-z\-]+%s$`, tld))
    return re.MatchString(domain)
}

func New(keywords, tlds, matchers []string) *Matcher {
    return &Matcher{
        Keywords: keywords,
        TLDs:     tlds,
        Matchers: matchers,
    }
}

func (m *Matcher) Match(certificates types.Message, keywords, tlds, matchers []string, certs int) {

    go func() {
        // Inicializa a variável patterns com o valor 0.
        patterns := 0

        // Cria o cache com uma expiração padrão de 5 minutos.
        c := cache.New(2*time.Minute, 10*time.Minute)

        // Remove o "*" prefixo do domínio e armazena em 'domain'.
        domain := strings.Replace(certificates.Domain, "*.", "", -1)

        // Monta a URL para a requisição.
        url := fmt.Sprintf("https://%s", domain)

        var pattern bool
        var context string

        // Verifica se a resposta já está em cache.
        if cachedResponse, ok := c.Get(url); ok {
            // Se a resposta estiver em cache, utiliza a resposta armazenada em cache.
            log.Info().Msgf("Found cached response for url %s", url)
            doc, err := goquery.NewDocumentFromReader(bytes.NewReader(cachedResponse.([]byte)))
            if err != nil {
                log.Warning().Msgf("error parsing cached response for url %s: %s", url, err)
                return
            }
            // Verifica se há correspondência com os matchers utilizando expressões regulares.
            for _, matcher := range m.Matchers {
                re, err := regexp.Compile(matcher)
                if err != nil {
                    fmt.Sprintf("Erro ao compilar expressão regular %s: %s", matcher, err)
                    continue
                }
                if re.MatchString(doc.Text()) {
                    log.Info().Msgf("Matcher %s found on cached response for %s", matcher, url)
                    patterns++
                    break
                }
            }
        } else {
            // Se a resposta não estiver em cache, faz a requisição HTTP.
            client := &http.Client{
                Timeout: 60 * time.Second,
            }

            req, err := http.NewRequest("GET", url, nil)
            if err != nil {
                log.Warning().Msgf("error creating HTTP request for url %s: %s", url, err)
                return
            }

            resp, err := client.Do(req)
            if err != nil {
                log.Warning().Msgf("error fetching HTTP response for url %s: %s", url, err)
                return
            }
            defer resp.Body.Close()

            // Lê o corpo da resposta e armazena em um buffer de bytes
            bodyBytes, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                log.Warning().Msgf("error reading response body for domain %s: %s", url, err)
                return
            }

            // Cria um bytes.Reader para o conteúdo do corpo da resposta
            bodyReader := bytes.NewReader(bodyBytes)


            // Faz o parse do response utilizando o goquery
            doc, err := goquery.NewDocumentFromReader(bodyReader)
            if err != nil {
                log.Warning().Msgf("error Parse response for url %s: %s", url, err)
                return
            }

            // Armazena a resposta em cache
            c.Set(url, bodyReader, cache.DefaultExpiration)


    
            // Verifica se há correspondência com os matchers utilizando expressões regulares.
            for _, matcher := range m.Matchers {
                re, err := regexp.Compile(matcher)
                if err != nil {
                    log.Debug().Msgf("Error %s found on %s", matcher, err)
                    continue
                }
                if re.MatchString(doc.Text()) {
                    log.Debug().Msgf("Matcher %s found on %s", matcher, url)
                    context = matcher
                    pattern = true
                    patterns++
                    break
                }
            }
        }
        var matchTld bool
        // Verifica se o domínio do objeto certificates termina com algum TLD.
        for _, tld := range m.TLDs {
            if hasTLD(certificates.Domain, tld) {
                log.Debug().Msgf("Domain %s matched TLDs (Top-Level Domains)", url)
                // Incrementa patterns em 1 se houver uma correspondência e sai do loop.
                matchTld = true
                patterns++
                break
            }
        }
        var keywors string
        // Verifica se o campo SubjectAltName do objeto certificates contém alguma palavra-chave.
        for _, keyword := range m.Keywords {
            if strings.Contains(certificates.Domain, keyword) {
                // Incrementa patterns em 1 se houver uma correspondência e sai do loop.
                keywors = keyword
                patterns++
                break
            }
        }

        // Define o nível de gravidade com base no número de correspondências encontradas.
        var levels severity.Severity
        switch {
        case patterns >= 2:
            levels = severity.High
        case patterns >= 1:
            levels = severity.Medium
        default:
            levels = severity.Low
        }

        log.Debug().Msgf("%d %v %s %v", levels, pattern, context, matchTld)
        // Logs the event source and the number of certificates processed so far.
        log.Info().Msgf("Number of certificates issued %d\n", certs)
        core.Log(certificates, keywors, levels, tlds, matchers)
    }()
}
