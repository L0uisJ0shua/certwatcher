package matchers

import (
   
    "github.com/PuerkitoBio/goquery"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    "pkg/core"
    "pkg/types"
    log "github.com/projectdiscovery/gologger"
    "github.com/patrickmn/go-cache"
    "fmt"
    "net/http"
    "io/ioutil"
    "time"
    "bytes"
    "regexp"
    "strings"
    "sync"


)

type Matcher struct {
    Keywords []string
    TLDs     []string
    Matchers []string
}

type RequestParams struct {
    Method string
    Paths  []string
}

type getResult struct {
    doc        *goquery.Document
    statusCode int
    err        error
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

func Get(url string, params *RequestParams) (*goquery.Document, int, error) {
    
    client := &http.Client{
        Timeout: 30 * time.Second,
    }

    // Cria um canal para receber os resultados das goroutines
    results := make(chan getResult)

    // Cria uma WaitGroup para esperar todas as goroutines terminarem
    var wg sync.WaitGroup

    for _, path := range params.Paths {
        wg.Add(1)
        go func(path string) {
            defer wg.Done()

            // Monta a URL para a requisição.
            url := fmt.Sprintf("%s%s", url, path)
            req, err := http.NewRequest(params.Method, url, nil)
            if err != nil {
                results <- getResult{err: err}
                return
            }

            resp, err := client.Do(req)
            if err != nil {
                results <- getResult{err: err}
                return
            }
            defer resp.Body.Close()

            if resp.StatusCode == http.StatusOK {
                // Lê o corpo da resposta e armazena em um buffer de bytes
                bodyBytes, err := ioutil.ReadAll(resp.Body)
                if err != nil {
                    results <- getResult{err: err}
                    return
                }

                // Cria um bytes.Reader para o conteúdo do corpo da resposta
                bodyReader := bytes.NewReader(bodyBytes)

                // Faz o parse do response utilizando o goquery
                doc, err := goquery.NewDocumentFromReader(bodyReader)
                if err != nil {
                    results <- getResult{err: err}
                    return
                }
                results <- getResult{doc: doc, statusCode: resp.StatusCode}
            } 
        }(path)
    }

    // Fecha o canal quando todas as goroutines terminarem
    go func() {
        wg.Wait()
        close(results)
    }()

    // Coleta os resultados das goroutines
    var doc *goquery.Document
    var statusCode int
    for result := range results {
        if result.err != nil {
            continue
        }
    
        doc = result.doc
        statusCode = result.statusCode
    }

    // Retorna os resultados finais
    if doc != nil {
        return doc, statusCode, nil
    } else {
        return nil, 0, fmt.Errorf("no successful response for url %s", url)
    }
}


func HashTLD(domain string, tld string) bool {
    // Verifica se o TLD tem pelo menos duas letras e é composto apenas por caracteres alfanuméricos
    if len(tld) < 2 || !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(tld) {
        return false
    }

    // Separa o domínio em partes, usando o ponto como delimitador
    parts := strings.Split(domain, ".")
    if len(parts) < 2 {
        return false
    }

    // Verifica se a última parte do domínio é o TLD desejado
    return parts[len(parts)-1] == tld
}

func New(keywords, tlds, matchers []string) *Matcher {
    return &Matcher{
        Keywords: keywords,
        TLDs:     tlds,
        Matchers: matchers,
    }
}

func (m *Matcher) Match(certificates types.Message, keywords, tlds, matchers []string, certs int, requests types.Request, level string) {

    go func() {

        // Inicializa a variável patterns com o valor 0.
        patterns := 0

        // Cria o cache com uma expiração padrão de 5 minutos.
        c := cache.New(60*time.Second, 160*time.Second)

        // Remove o "*" prefixo do domínio e armazena em 'domain'.
        domain := strings.Replace(certificates.Domain, "*.", "", -1)

        // Monta a URL para a requisição.
        url := fmt.Sprintf("https://%s", domain)

        var matcherMatched string
        // Verifica se a resposta já está em cache.
        if cached, ok := c.Get(url); ok {
            // Se a resposta estiver em cache, utiliza a resposta armazenada em cache.
            log.Info().Msgf("Found cached response for url %s", url)
            doc, err := goquery.NewDocumentFromReader(bytes.NewReader(cached.([]byte)))
            if err != nil {
                log.Warning().Msgf("Error parsing cached response for url %s: %s", url, err)
                return
            }
            // Verifica se há correspondência com os matchers utilizando expressões regulares.
            for _, matcher := range m.Matchers {
                re, err := regexp.Compile(matcher)
                if err != nil {
                    log.Warning().Msgf("%s", err)
                    continue
                }
                if re.MatchString(doc.Text()) {
                    matcherMatched = matcher
                    continue
                }
            }
        } else {

            params := &RequestParams{
                Method: requests.Method,
                Paths:  requests.Path,
            }

            // Se a resposta não estiver em cache, faz a requisição HTTP.
            doc, _, err := Get(url, params)

            if err != nil {
                log.Warning().Msgf("%s", err)
                return
            }
            
            // Verifica se há correspondência com os matchers utilizando expressões regulares.
            for _, matcher := range m.Matchers {
                re, err := regexp.Compile(matcher)
                if err != nil {
                    continue
                }
                if re.MatchString(doc.Text()) {
                    matcherMatched = matcher
                    log.Debug().Msgf("Matcher %s found on %s", matcher, url)
                    continue
                }
            }
        }
        // Verifica se o domínio do objeto certificates termina com algum TLD.
        var tldMatched bool
        for _, tld := range m.TLDs {
            if HashTLD(certificates.Domain, tld) {
                log.Debug().Msgf("Domain %s matched TLDs (Top-Level Domains)", url)
                // Incrementa patterns em 1 se houver uma correspondência e sai do loop.
                patterns++
                tldMatched = true
                break
            }
        }
        var keywdors string
        // Verifica se o campo SubjectAltName do objeto certificates contém alguma palavra-chave.
        for _, keyword := range m.Keywords {
            if strings.Contains(certificates.Domain, keyword) {
                // Incrementa patterns em 1 se houver uma correspondência e sai do loop.
                keywdors = keyword
                break
            }
        }

        var levels severity.Severity
        switch {
        case patterns >= 1:
            levels = severity.Medium
        default:
            levels = severity.Low
        }

        level, err := Severity(level)

        if err != nil {
            log.Info().Msgf("%s", err)
        } 

        if len(keywdors) > 0 {
            log.Info().Msgf("Suspicious activity found at %s\n", time.Now().Format("01-02-2006 15:04:05"))
            log.Info().Msgf("Number of certificates issued: %d\n", certs)
            if len(matcherMatched) > 0 {
                log.Info().Msgf("Matching regular expression found: %s", matcherMatched)
                core.Log(certificates, keywdors, severity.High, tlds, matchers)
                return
            } else if tldMatched {
                log.Info().Msg("Domain matched TLDs (Top-Level Domains)")
            }
            core.Log(certificates, keywdors, levels, tlds, matchers)
        } else {
          
            if len(matcherMatched) > 0 {
                log.Info().Msgf("Pattern successfully found %s", time.Now().Format("01-02-2006 15:04:05"))
                log.Info().Msgf("Number of certificates issued: %d\n", certs)
                log.Info().Msgf("Matching regular expression found: %s", matcherMatched)
                core.Log(certificates, keywdors, level, tlds, matchers)
                return
            }
        }   
 
    }()
}
