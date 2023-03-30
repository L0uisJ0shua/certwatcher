package utils

import (
    "strings"
)

func Unique(strings []string) []string {
    // Create a map to store unique strings
    uniqueStrings := make(map[string]bool)

    // Loop through the input slice and add each string to the map
    for _, str := range strings {
        uniqueStrings[str] = true
    }

    // Create a slice to hold the unique strings
    uniqueSlice := make([]string, 0, len(uniqueStrings))

    // Loop through the map and append each key (unique string) to the slice
    for str := range uniqueStrings {
        uniqueSlice = append(uniqueSlice, str)
    }

    // Return the slice of unique strings
    return uniqueSlice
}

func Author(name string) string {
    names := strings.Split(name, " ")
    var Author []string
    for _, name := range names {
        Author = append(Author, strings.ToLower(name))
    }
    return "@" + strings.Join(Author, "")
}

func RemoveWildcardPrefix(url string) string {
    // Verificando se a URL começa com '*' e se possui pelo menos dois caracteres
    if strings.HasPrefix(url, "*.") && len(url) > 1 {
        // Retornando a URL a partir do segundo caractere
        return url[2:]
    }
    // Caso não tenha prefixo de wildcard, retornamos a URL original
    return url
}
