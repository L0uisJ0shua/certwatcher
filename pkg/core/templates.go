package core

import (
    "pkg/types"
    "github.com/logrusorgru/aurora/v4"
    log "github.com/projectdiscovery/gologger"
    yaml "pkg/yamlreader"
	template "pkg/templates"
    "strings"
    "pkg/utils"
)

func Templates(options types.Options) ([]string, []string, []string) {

    // Find templates using the given options
    templates, _ := template.Find(options.Templates)

    // Initialize a map to store tags for each loaded YAML
    tagsMap := make(map[string]map[string]bool)

    // Initialize variables to store keywords, tlds, tags, matchers, and a template instance
    var keywords, tlds, matchers []string
    var template types.Templates

    // Initialize a map to keep track of processed templates
    processedTemplates := make(map[string]bool)

    // Loop through each template and extract relevant information
    for _, path := range templates {
        // Read the YAML file and unmarshal into the template instance
        var currentTemplate string
        if err := yaml.ReadYAML(path, &template); err != nil {
            log.Fatal().Msgf("Template error %s", err)
        }

        // Skip processing if template has already been processed
        if processedTemplates[template.Info.ID] {
            continue
        }

        currentTemplate = template.Info.Name

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

        // Print information about the current template
        tagSlice := make([]string, 0, len(tagsMap[template.Info.ID]))
        for tag := range tagsMap[template.Info.ID] {
            tagSlice = append(tagSlice, tag)
        }
        
        log.Info().Msgf("[%s] %s %s [%s]", aurora.Bold(template.Info.ID), aurora.Bold(currentTemplate), aurora.Bold(utils.Author(template.Info.Author)), aurora.BrightCyan(strings.Join(tagSlice, ", ")))

        // Mark template as processed
        processedTemplates[template.Info.ID] = true
    }

    // Create a slice with unique tags from the tag map
    var tags []string
    for _, tagMap := range tagsMap {
        for tag := range tagMap {
            tags = append(tags, tag)
        }
    }

    // Print summary information about loaded templates, tags, and keywords
    if len(options.Templates) > 0 {
        log.Info().Msgf("Templates have been loaded: %d", len(options.Templates))
        if len(keywords) > 0 {
            log.Info().Msgf("A total of %d keywords have been loaded", len(keywords))
        } else if len(tags) > 0 {
            log.Info().Msgf("A total of %d unique tags have been loaded", len(tags))
        } 
        log.Info().Msgf("A total of %d unique matchers have been loaded", len(matchers))
    } else {
       log.Fatal().Msg("Templates with IDs not found")
    }

    // Print summary information about loaded TLDs if any have been loaded
    if len(tlds) > 0 {
        log.Info().Msgf("A total of %d TLDs (Top-Level Domains) have been loaded", len(tlds))
    }

    // Return the collected keywords, tlds, and matchers
    return keywords, tlds, matchers
}


