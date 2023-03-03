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
    tagsMap := make(map[string][]string)

    // Initialize variables to store keywords, tlds, tags, matchers, and a template instance
    var keywords, tlds, tags, matchers []string
    var template types.Templates

    // Loop through each template and extract relevant information
    for _, path := range templates {
        // Read the YAML file and unmarshal into the template instance
        if err := yaml.ReadYAML(path, &template); err != nil {
            log.Fatal().Msgf("Template error %s", err)
        }

         // Append tags to the tag map for the current template
        for _, tag := range template.Info.Classification.Tags {
            tagsMap[template.Info.ID] = append(tagsMap[template.Info.ID], tag)
        }

        // Append keywords, tags, tlds, and matchers to their respective slices
        keywords = append(keywords, template.Info.Keywords...)
        tags = append(tags, template.Info.Classification.Tags...)
        for _, tld := range template.Info.Tlds {
            tlds = append(tlds, tld.Pattern)
        }
        for _, matcher := range template.Info.Matchers {
            matchers = append(matchers, matcher.Pattern)
        }

        // Print debug information about loaded TLDs
        log.Debug().Msgf("%v %v", template.Info.Matchers, template.Info.Tlds)
        log.Debug().Msgf("A total of %d tlds have been loaded", len(tlds))
    }

    // Print summary information about loaded templates, tags, and keywords
    log.Info().Msgf("Templates have been loaded %d", len(options.Templates))
    for id, tags := range tagsMap {
        log.Info().Msgf("[%s] [%s]", aurora.Bold(id), aurora.BrightCyan(strings.Join(tags, ", ")))
    }

    // Return the collected tags for each loaded YAML
    var tag []string
    for _, tags := range tagsMap {
        tag = append(tag, tags...)
    }

    log.Info().Msgf("A total of %d keywords have been loaded", len(keywords))

    // Print summary information about loaded TLDs if any have been loaded
    if len(tlds) > 0 {
        log.Info().Msgf("Matchers TLDs (Top-Level Domains) %d", len(tlds))
    }

    // Return the collected keywords, tlds, and matchers
    return keywords, tlds, matchers
}
