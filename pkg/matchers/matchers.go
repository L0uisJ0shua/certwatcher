package matchers

import (
    "strings"
)

// KeywordMatch verifica se a palavra-chave está contida na string de entrada (ignorando o case)
func Contains(input string, keyword string) bool {
    return strings.Contains(strings.ToLower(input), strings.ToLower(keyword))
}