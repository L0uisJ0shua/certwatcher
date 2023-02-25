package core

import (
    "pkg/utils"
    "pkg/types"
    "github.com/logrusorgru/aurora/v4"
    "github.com/projectdiscovery/gologger"
    yaml "pkg/yamlreader"
	template "pkg/templates"
)

func Templates(options types.Options) ([]string, []string, []string) {
    templates, _ := template.Find(options.Templates)
    var keywords []string
    var tlds []string
    var tags []string
    var template types.Templates

    for _, path := range templates {

        gologger.Debug().Msgf("template directory %s", path)

        err := yaml.ReadYAML(path, &template)
        if err != nil {
            gologger.Fatal().Msgf("template error %s", err)
        }

        keywords = append(keywords, template.Info.Keywords...)
        tags = append(tags, template.Info.Classification.Tags...)

        // Convert the []struct to []string
        for _, tld := range template.Info.Tlds {
            tlds = append(tlds, tld.Pattern)
        }

        gologger.Debug().Msgf("A total of %d tlds have been loaded", len(tlds))

    }

    // Show how many templates have been loaded.

    display := utils.JoinWithCommas(template.Info.Classification.Tags)
    gologger.Info().Msgf("Templates have been loaded %d", len(options.Templates))
    gologger.Info().Msgf("[%s] %s (%s) [%s]", aurora.White(template.Info.ID), aurora.White(template.Info.Name), aurora.White(utils.JoinWithAt(template.Info.Author)), aurora.Cyan(display))
    gologger.Info().Msgf("A total of %d keywords have been loaded", len(keywords))

    // Show how many Tlds have been loaded.
    if len(tlds) > 0 {
        gologger.Info().Msgf("Matchers TLDs (Top-Level Domains) %d", len(tlds))
    }
    return keywords, tlds, tags
}
