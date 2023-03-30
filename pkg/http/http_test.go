package http

import (
	"fmt"
	"pkg/http"
	"testing"
)

func TestRequestsCache3(t *testing.T) {
	// Create requests with multiple paths
	req := &http.Request{
		Paths: []string{
			"/",
			"/.env",
			"/.git/config",
			"/.git/.env",
			"/wp-admin",
			"/admin",
			"/.well-known/acme-challenge/letsencrypt",
			"/.gitignore",
			"/.svn",
			"/.DS_Store",
			"/index.php",
			"/login.php",
			"/wp-includes/",
			"/phpmyadmin/",
			"/administrator/",
		},
		Method:    "GET",
		Condition: "or",
	}

	// Define subdomains and URLs to test
	subdomains := []string{"www", "blog", "shop", "prod", "client"}
	domains := []string{"yahoo.com", "google.co.in", "afghanapi.khudkar.com"}

	results := make(map[string][]int)

	for _, domain := range domains {
		for _, subdomain := range subdomains {
			url := fmt.Sprintf("https://%s.%s", subdomain, domain)

			_, status, sizes, err := http.Requests(url, req)

			if err != nil {
				// Add failed request to results map
				results[url] = []int{-1}
				continue
			}

			// Add successful request to results map
			results[url] = status

			t.Log(status, sizes, err)

		}
	}

	// Print results
	for url, status := range results {
		if status[0] == -1 {
			t.Logf("Failed request to %s", url)
		} else {
			t.Logf("Successful request to %s with status code(s): %v", url, status)
		}
	}
}

func TestRequests(t *testing.T) {
	url := "https://www.google.com"
	req := &http.Request{
		Paths:     []string{"/", "/search?q=golang"},
		Method:    "GET",
		Condition: "",
	}
	resp, status, sizes, err := http.Requests(url, req)
	if err != nil {
		t.Errorf("error received: %v", err)
	}
	if resp == nil {
		t.Errorf("no response received")
	}
	if len(status) == 0 {
		t.Errorf("no status received")
	}
	if len(sizes) == 0 {
		t.Errorf("no sizes received")
	}
}

func TestRequestsInvalidValues(t *testing.T) {
	// Create requests with invalid paths
	reqInvalidPaths := &http.Request{
		Paths: []string{
			"/",
			"//",
			"/path/../file",
			"\\windows\\file",
			"///some/url",
			"http://invalid-url.com",
			"https://invalid-url.com",
			"ftp://invalid-url.com",
			"mailto:user@example.com",
			"javascript:alert('xss')",
		},
		Method: "GET",
	}

	// Define invalid domains and URLs to test
	invalidDomains := []string{"invalid$domain", "invalid&domain", "invalid^domain"}
	invalidURLs := []string{"invalid_url", "invalid:url", "invalid;url", "invalid url", "invalid:url.com"}

	// Test with invalid domains
	for _, domain := range invalidDomains {
		url := fmt.Sprintf("https://%s", domain)
		_, _, _, err := http.Requests(url, reqInvalidPaths)
		if err == nil {
			t.Errorf("Expected error with invalid domain: %s", domain)
		}
	}

	// Test with invalid URLs
	for _, invalidURL := range invalidURLs {
		url := fmt.Sprintf("https://%s", invalidURL)
		_, _, _, err := http.Requests(url, reqInvalidPaths)
		if err == nil {
			t.Errorf("Expected error with invalid URL: %s", invalidURL)
		}
	}

	// Test with invalid paths
	reqInvalidPaths.Paths = []string{"invalid-path", "/../path"}
	for _, domain := range []string{"example.com"} {
		url := fmt.Sprintf("https://%s", domain)
		_, _, _, err := http.Requests(url, reqInvalidPaths)
		if err == nil {
			t.Errorf("Expected error with invalid paths: %v", reqInvalidPaths.Paths)
		}
	}
}
