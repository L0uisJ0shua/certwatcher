package matchers

import (
    "regexp"
    "strings"
)

// KeywordMatch verifica se a palavra-chave está contida na string de entrada (ignorando o case)
func Contains(input string, keyword string) bool {
    return strings.Contains(strings.ToLower(input), strings.ToLower(keyword))
}

// RegexMatch verifica se a expressão regular corresponde à string de entrada
func RegexMatch(input string, regex string) bool {
    match, err := regexp.MatchString(regex, input)
    if err != nil {
        // Se houver um erro ao compilar a expressão regular, retorne false
        return false
    }
    return match
}