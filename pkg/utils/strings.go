package utils

import (
    "strings"
)

func Author(name string) string {
    names := strings.Split(name, " ")
    var Author []string
    for _, name := range names {
        Author = append(Author,  strings.ToLower(name))
    }
    return "@" + strings.Join(Author, "")
}