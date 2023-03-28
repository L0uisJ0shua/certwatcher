package matchers

import (
	"fmt"
	"regexp"
	"strings"
)

// MatchStatusCode verifica se um código de status HTTP corresponde a um ou mais códigos de status HTTP especificados no objeto Matcher.
func (m *Matcher) MatchStatusCodes(respStatusCodes, definedStatusCodes []int) ([]int, bool) {
	var matchedStatusCodes []int
	for _, definedStatus := range definedStatusCodes {
		for _, respStatus := range respStatusCodes {
			if respStatus == definedStatus {
				matchedStatusCodes = append(matchedStatusCodes, respStatus)
			}
		}
	}
	if len(matchedStatusCodes) > 0 {
		return matchedStatusCodes, true
	} else {
		return respStatusCodes, false
	}
}

// MatchSizes verifica se um tamanho corresponde a um ou mais tamanhos especificados no objeto Matcher.
func (m *Matcher) MatchSizes(respSize int, definedSizes []int) ([]int, bool) {
	var matchedSizes []int
	for _, definedSize := range definedSizes {
		if respSize == definedSize {
			matchedSizes = append(matchedSizes, respSize)
		}
	}
	if len(matchedSizes) > 0 {
		return matchedSizes, true
	}
	// log.Debug().Msgf("Response Size Not Match %d", respSize)
	return matchedSizes, false
}

// MatchTLD verifica se um tld existe no dominio e retorna true
func (matcher *Matcher) MatchTLD(domain string, tlds []string) (string, bool) {
	for _, tld := range tlds {

		re, err := regexp.Compile(tld)
		if err != nil {
			// Erro de compilação da expressão regular
			return fmt.Sprintf("%s", tld), false
		}

		if re.MatchString(domain) {
			// Retorna o TLD que deu match
			tld := re.FindString(domain)
			// Remove o ponto do início do TLD
			tld = strings.TrimPrefix(tld, ".")
			return tld, true
		}
	}
	// log.Debug().Msgf("Top Level Domains (%s) Not Match", domain)
	return "", false
}

// MatchKeywords verifica se um determinado domínio corresponde a um ou mais palavras-chave especificadas no objeto Matcher.
// Retorna as palavras-chave que correspondem e um valor booleano indicando se houve correspondência ou não.
func (matcher *Matcher) MatchKeywords(domain string, keywords []string) ([]string, bool) {
	// Prepara as palavras-chave, removendo espaços em branco e transformando em minúsculas
	for i, keyword := range keywords {
		keywords[i] = strings.ToLower(strings.TrimSpace(keyword))
	}

	// Prepara o domínio, transformando em minúsculas
	domain = strings.ToLower(domain)

	var matches []string
	for _, keyword := range keywords {
		// Verifica se a palavra-chave está contida no domínio
		if strings.Contains(domain, keyword) {
			matches = append(matches, keyword)
			continue
		}
	}

	return matches, true
}
