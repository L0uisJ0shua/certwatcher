package matchers

import (
	"errors"
	"regexp"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
)

func Parse(domain string) (*publicsuffix.DomainName, error) {
	parsed, err := publicsuffix.Parse(domain)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// MatchStatusCode matches a status code check against a response
func (matcher *Matcher) MatchStatusCode(statusCode int) (bool, error) {
	// Iterate over all the status codes accepted as valid
	for _, status := range matcher.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true, nil
	}
	return false, errors.New("No matching status code found in the HTTP request")
}

// MatchSize matches a size check against a response
func (matcher *Matcher) MatchSize(length int) (bool, error) {
	// Iterate over all the sizes accepted as valid
	for _, size := range matcher.Size {
		// Continue if the size doesn't match
		if length != size {
			continue
		}
		// Return on the first match.
		return true, nil
	}
	return false, errors.New("No matching body size found in the HTTP request.")
}

func (matcher *Matcher) MatchTLD(domain string) (bool, error) {
	parsed, err := Parse(domain)
	if err != nil {
		return false, errors.New("could not parse domain")
	}

	// Iterate over all the TLDs accepted as valid
	for _, valid := range matcher.TLDs {
		// If the valid TLD is a regex, check if it matches the parsed TLD
		re, err := regexp.Compile(valid)
		if err != nil {
			return false, errors.New("invalid regex pattern")
		}
		if re.MatchString(parsed.TLD) {
			return true, nil
		}
	}

	return false, nil
}

func (matcher *Matcher) MatchKeywords(domain string) ([]string, error) {
	// Remove all characters except letters, digits, hyphens and dots from the domain
	reg := regexp.MustCompile(`[^a-zA-Z0-9.-]`)
	domain = reg.ReplaceAllString(domain, "")

	var matches []string

	for _, keyword := range matcher.Keywords {
		// Remove all characters except letters and digits from the keyword
		reg := regexp.MustCompile(`[^a-zA-Z0-9]`)
		keyword = reg.ReplaceAllString(keyword, "")

		if strings.Contains(strings.ToLower(domain), strings.ToLower(keyword)) {
			matches = append(matches, keyword)
			continue
		}
	}

	if len(matches) > 0 {
		return matches, nil
	}

	return nil, errors.New("no matching keywords found")
}

func (matcher *Matcher) MatchRegex(response string) (bool, []string, error) {
	matchers := make([]string, 0)

	for _, regex := range matcher.Matchers {
		matched, err := regexp.MatchString(regex, response)
		if err != nil {
			return false, []string{}, nil
		}

		switch Condition := ConditionType(matcher.Condition); Condition {
		case ORCondition:
			if matched {
				match := regexp.MustCompile(regex).FindAllString(response, -1)
				matchers = append(matchers, match...)
				if !matcher.MatchAll {
					return true, matchers, nil
				}
			}
		case ANDCondition:
			if !matched {
				return false, []string{}, errors.New("no matching regex found")
			}
			match := regexp.MustCompile(regex).FindAllString(response, -1)
			matchers = append(matchers, match...)
		}
	}

	return len(matchers) > 0, matchers, errors.New("no matching regex found")
}
