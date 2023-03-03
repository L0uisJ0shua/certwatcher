// Package logger provides logging functionality
package core

import (
    "fmt"
    "regexp"
    "strings"
    log "github.com/projectdiscovery/gologger"
    "github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
    types "pkg/types"
    template "pkg/templates"
    utils "pkg/utils"
     "github.com/PuerkitoBio/goquery"
     "net/http"
     "time"
     "context"
)

const (
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
	httpTimeout = time.Second * 5
)

// Verificar se o domínio suporta HTTPS
func supportsHTTPS(domain string) bool {
    // Cria uma nova requisição HTTP para o domínio
    req, err := http.NewRequest("GET", "https://"+domain, nil)
    if err != nil {
        log.Warning().Msgf("[DEBUG] [http-request] Failed to create HTTP request to %s: %s\n", domain, err)
        return false
    }

    // Define um tempo limite para a solicitação
    client := http.Client{
        Timeout: time.Second * 5,
    }

    // Envie a solicitação e verifique se ocorreu um erro
    resp, err := client.Do(req)
    if err != nil {
        log.Warning().Msgf("[DEBUG] [http-request] Failed to make HTTPS request to %s: %s\n", domain, err)
        return false
    }

    // Verifique se a resposta foi bem-sucedida (código 2xx)
    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
        return true
    }

    // Se a resposta não foi bem-sucedida, o domínio não suporta HTTPS
    return false
}


// Logs a message with the specified ID, severity, and domain,
// along with an array of message strings.
func LogMsg(id, name string, severity severity.Severity, domain string, message []string) {
    fmt.Printf("%s\n", template.Message(id, name, severity, domain, message))
}

// Certificate checks for TLD matches and logs messages using LoggLogMsger
func Log(certificates types.Message, keyword string, tlds []string, matchers []string) {

    // Cria o cliente HTTP com o timeout configurado
    httpClient := &http.Client{
        Timeout: httpTimeout,
    }

    // Cria um mapa para armazenar as respostas HTTP cacheadas
    cache := make(map[string]*http.Response)

    // Itera por todas as TLDs
    for _, tld := range tlds {
        // Verifica se a TLD corresponde ao domínio do certificado
        if matched, _ := regexp.MatchString(tld, certificates.Domain); matched {
            // Remove o prefixo "*" do domínio e armazena em 'domain'
            domain := strings.Replace(certificates.Domain, "*.", "", -1)

            if supportsHTTPS(domain) {
                domain = "https://" + domain
                log.Debug().Msgf("O domínio %s %s", domain, "suporta HTTPS!")
            } else {
                domain = "http://" + domain
                log.Debug().Msgf("O domínio %s %s", domain, "não suporta HTTPS.")
            }

            log.Info().Msgf("Domain %s matched TLDs (Top-Level Domains)", domain)

            // Verifica se a resposta HTTP está cacheada
            if resp, ok := cache[domain]; ok {
                defer resp.Body.Close()
            }

            ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
            defer cancel()
            
            req, err := http.NewRequestWithContext(ctx, http.MethodGet, domain, nil)
            if err != nil {
                log.Warning().Msgf("[DEBUG] [http-request] failed to create HTTP request to %s: %s\n", domain, err)
                return
            }

            // Define o User-Agent da requisição
            req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")

            // Executa a requisição HTTP
            resp, err := httpClient.Do(req)
            if err != nil {
                log.Warning().Msgf("[DEBUG] [http-request] failed to create HTTP request to %s: %s\n", domain, err)
                return
            }
            defer resp.Body.Close()

            // Armazena a resposta HTTP no cache
            cache[domain] = resp

            // Cria um documento GoQuery a partir da resposta HTTP
            doc, err := goquery.NewDocumentFromReader(resp.Body)
            if err != nil {
                log.Debug().Msgf("[DEBUG] [http-response] failed to parse response body as HTML from %s", domain)
                return
            }

            log.Debug().Msgf("[DEBUG] [http-request] success to create HTTP request to %s\n", domain)

            // Itera por todos os matchers
            for _, matcher := range matchers {
                var match string
                switch {
                    // Verifica se o matcher é um seletor CSS ou XPath
                    case strings.HasPrefix(matcher, "//"), strings.HasPrefix(matcher, "#"):
                        if doc.Find(matcher).Length() > 0 {
                            match = matcher
                            log.Info().Msgf("Matcher %s found on %s", match, domain)
                        }
                    // Caso contrário, verifica se o matcher existe no corpo da página
                    default:
                        if strings.Contains(doc.Text(), matcher) || regexp.MustCompile(matcher).MatchString(doc.Text()) {
                            match = matcher
                            log.Info().Msgf("Matcher %s found on %s", match, domain)
                            Message(certificates, keyword, severity.High, utils.JoinWithCommas(certificates.Domains), strings.Split(certificates.Issuer, ","))
                            return
                        }
                }
            }
        }
    }
    log.Info().Msgf("No matchers or TLDs matched")
    Message(certificates, keyword, severity.Low, utils.JoinWithCommas(certificates.Domains), strings.Split(certificates.Issuer, ","))
}

// Message logs multiple messages using LogMsg
func Message(certificates types.Message, keyword string, severity severity.Severity, domains string, issuer []string) {

    // Type of protocols
    protocols := types.Protocols {
	    DNS: "dns",
        SSL: "ssl",
        Log: "log",
	}

    logs := []struct {
        id       string
        name     string
        message  []string
    }{
        {"ssl-dns-names", protocols.DNS, strings.Split(domains, " ")},
        {"issuer", protocols.SSL, issuer},
        {"keyword", keyword, strings.Split(certificates.SubjectAltName, " ")},
        {"source", protocols.Log, strings.Split(certificates.Source, " ")},
    }

    for _, log := range logs {
        LogMsg(log.id, log.name, severity, certificates.Domain, log.message)
    }
}
