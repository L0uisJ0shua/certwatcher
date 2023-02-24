package matchers

import (
    "strings"
)

func Contains(domain string, pattern string) bool {
    return strings.Contains(strings.ToLower(domain), strings.ToLower(pattern))
}