package main

import (
    "pkg/matchers"
    "testing"
)

func TestMatchRegex(t *testing.T) {
    // Test OR condition with MatchAll false
    m := matchers.Matcher{
        Matchers:  []string{"apple", "banana", "cherry"},
        Condition: "or",
        MatchAll:  true,
    }
    if result, _ := m.MatchRegex("cherry apple banana"); !result {
        t.Error("Expected true, got false")
    }

    // Test AND condition with MatchAll false
    m = matchers.Matcher{
        Matchers:  []string{"apple", "banana", "melon"},
        Condition: "and",
        MatchAll:  true,
    }
    if result, _ := m.MatchRegex("apple"); result {
        t.Error("Expected false, got true")
    }
}

func TestMatchStatusCode(t *testing.T) {
    // Create a new matcher
    m := &matchers.Matcher{
        Status: []int{200, 201},
    }

    // Test for a matching status code
    if ok, err := m.MatchStatusCode(200); err != nil || !ok {
        t.Errorf("Expected (true, nil), got (%v, %v)", ok, err)
    }

    // Test for a non-matching status code
    if ok, err := m.MatchStatusCode(404); err == nil || ok {
        t.Errorf("Expected (false, error), got (%v, %v)", ok, err)
    }
}

func TestMatchTLD(t *testing.T) {
    // Create a new matcher
    m := &matchers.Matcher{
        TLDs: []string{"com", "net"},
    }

    // Test for a matching TLD
    if ok, err := m.MatchTLD("example.com"); err != nil || !ok {
        t.Errorf("Expected (true, nil), got (%v, %v)", ok, err)
    }

    // Test for a non-matching TLD
    if ok, err := m.MatchTLD("example.org"); err == nil || ok {
        t.Errorf("Expected (false, error), got (%v, %v)", ok, err)
    }
}

func TestMatchSize(t *testing.T) {
    matcher := matchers.Matcher{
        Size: []int{100, 200},
    }

    // Test with valid length
    if ok, err := matcher.MatchSize(100); err != nil || !ok {
        t.Errorf("Expected (true, nil), got (%v, %v)", ok, err)
    }

    // Test with invalid length
    if ok, err := matcher.MatchSize(50); err == nil || ok {
        t.Errorf("Expected (false, error), got (%v, %v)", ok, err)
    }
}
