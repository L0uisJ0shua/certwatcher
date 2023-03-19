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

func addPathsToSlice(params *RequestParams) []string {
    var Paths []string

      // verifica se params.Paths é igual a zero e adiciona "/" ao slice "Paths" caso seja
    if len(Paths) == 0 {
        Paths = append(Paths, "/")
    }
    
    // adiciona o conteúdo de "params.Paths" ao slice "Paths"
    Paths = append(Paths, params.Paths...)

    // imprime o slice e o seu tamanho
    log.Debug().Msgf("Slice: %q\nTamanho: %d\n", Paths, len(Paths))
    
    return Paths
}

func Get(url string, params *RequestParams) (*goquery.Document, int, error) {
    // Cria um cliente HTTP com timeout definido em 30 segundos
    client := &http.Client{
        Timeout: 30 * time.Second,
    }

    var paths = addPathsToSlice(params)

    // Cria um canal para receber os resultados das goroutines
    results := make(chan getResult, len(paths))

    // Cria uma WaitGroup para esperar todas as goroutines terminarem
    var wg sync.WaitGroup

    // Armazena as URLs completas das solicitações enviadas
    requests := make([]string, 0, len(paths))

    // Realiza as solicitações em paralelo
    for _, path := range paths {
        wg.Add(1)

        // Monta a URL para a requisição
        reqURL := url + path

        // Adiciona a URL completa na lista de solicitações
        requests = append(requests, reqURL)

        log.Debug().Msgf("%s", reqURL)

        go func(url string, method string) {
            defer wg.Done()

            // Cria uma nova requisição HTTP com o método especificado
            req, err := http.NewRequest(method, url, nil)
            if err != nil {
                results <- getResult{err: err}
                return
            }

            // Envia a requisição e espera pela resposta
            resp, err := client.Do(req)
            if err != nil {
                results <- getResult{err: err}
                return
            }
            defer resp.Body.Close()

            // Verifica se a resposta teve sucesso (status code 200)
            if resp.StatusCode != http.StatusOK {
                results <- getResult{err: fmt.Errorf("response status code: %d", resp.StatusCode)}
                return
            }

            // Faz o parse do response utilizando o goquery
            doc, err := goquery.NewDocumentFromReader(resp.Body)
            if err != nil {
                results <- getResult{err: err}
                return
            }

            results <- getResult{doc: doc, statusCode: resp.StatusCode}
        }(reqURL, params.Method)
    }

    // Fecha o canal quando todas as goroutines terminarem
    go func() {
        wg.Wait()
        close(results)
    }()

    // Coleta os resultados das goroutines
    var doc *goquery.Document
    var statusCode int
    var err error
    for result := range results {
        if result.err != nil {
            err = result.err
            continue
        }

        doc = result.doc
        statusCode = result.statusCode
        break
    }

    // Imprime a lista de solicitações
    // log.Debug().Msgf("Number of Requests Sent: %v\n", requests)

    // Returns the final results
    if doc != nil {
        log.Debug().Msgf("Successfully received response for requests: %v\n", requests)
        return doc, statusCode, nil
    } else if err != nil {
        log.Warning().Msgf("Encountered an error during request: %v", err)
        return nil, 0, err
    } else {
        log.Warning().Msgf("No successful response received for url: %s", url)
        return nil, 0, nil
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

func (m *Matcher) Match(certificates types.Message, keywords, tlds, matchers []string, certs int, requests types.Request, level string, paths []string) {

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
                    break
                }
                if re.MatchString(doc.Text()) {
                    matcherMatched = matcher
                    break
                }
            }
        } else {

            params := &RequestParams{
                Method: requests.Method,
                Paths:  paths,
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
                    break
                }
                if re.MatchString(doc.Text()) {
                    matcherMatched = matcher
                    break
                }
            }
        }
        // Verifica se o domínio do objeto certificates termina com algum TLD.
        var tldMatched bool
        for _, tld := range m.TLDs {
            if HashTLD(certificates.Domain, tld) {
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

        level, _ := Severity(level)

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
