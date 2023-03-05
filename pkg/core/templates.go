package core

import (
    "pkg/types"
    "github.com/logrusorgru/aurora/v4"
    log "github.com/projectdiscovery/gologger"
    yaml "pkg/yamlreader"
	template "pkg/templates"
    "strings"
)

func Templates(options types.Options) ([]string, []string, []string) {

    // Find templates using the given options
    templates, _ := template.Find(options.Templates)

    // Initialize a map to store tags for each loaded YAML
    tagsMap := make(map[string]map[string]bool)

    // Initialize variables to store keywords, tlds, tags, matchers, and a template instance
    var keywords, tlds, matchers []string
    var template types.Templates

    // Loop through each template and extract relevant information
    for _, path := range templates {
        // Read the YAML file and unmarshal into the template instance
        if err := yaml.ReadYAML(path, &template); err != nil {
            log.Fatal().Msgf("Template error %s", err)
        }

        // Append tags to the tag map for the current template
        if _, ok := tagsMap[template.Info.ID]; !ok {
            tagsMap[template.Info.ID] = make(map[string]bool)
        }
        for _, tag := range template.Info.Classification.Tags {
            tagsMap[template.Info.ID][tag] = true
        }

        // Append keywords, tags, tlds, and matchers to their respective slices
        keywords = append(keywords, template.Info.Keywords...)
        for _, tld := range template.Info.Tlds {
            tlds = append(tlds, tld.Pattern)
        }
        for _, matcher := range template.Info.Matchers {
            matchers = append(matchers, matcher.Pattern)
        }
    }

    // Create a slice with unique tags from the tag map
    var tags []string
    for _, tagMap := range tagsMap {
        for tag := range tagMap {
            tags = append(tags, tag)
        }
    }

    // Print summary information about loaded templates, tags, and keywords
    log.Info().Msgf("Templates have been loaded %d", len(options.Templates))
    for id, tagMap := range tagsMap {
        tagSlice := make([]string, 0, len(tagMap))
        for tag := range tagMap {
            tagSlice = append(tagSlice, tag)
        }
        log.Info().Msgf("[%s] [%s]", aurora.Bold(id), aurora.BrightCyan(strings.Join(tagSlice, ", ")))
    }

    log.Info().Msgf("A total of %d keywords have been loaded", len(keywords))

    // Print summary information about loaded TLDs if any have been loaded
    if len(tlds) > 0 {
        log.Info().Msgf("Matchers TLDs (Top-Level Domains) %d", len(tlds))
    }

    // Return the collected keywords, tlds, and matchers
    return keywords, tlds, matchers
}
