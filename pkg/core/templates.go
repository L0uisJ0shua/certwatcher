package core

import (
    "pkg/types"
    "github.com/logrusorgru/aurora/v4"
    log "github.com/projectdiscovery/gologger"
    yaml "pkg/yamlreader"
	template "pkg/templates"
    "strings"
    "pkg/utils"
    "internal/colorizer"
    "fmt"
)

type Models struct {
    Keywords []string `yaml:"keywords"`
    Matchers []string `yaml:"matchers"`
    TLDs     []string `yaml:"tlds"`
    Severity   string `yaml:"severity"`
    Requests  types.Request `yaml:"requests"`
}

var colorize func(interface{}) string

func init() {
    c := colorizer.New()
    colorize = func(s interface{}) string {
        return c(fmt.Sprint(s))
    }
}

func Info(template types.Templates, currentTemplate string, tagSlice []string) {

    severity := template.Info.Severity
  
    logMsg := fmt.Sprintf("[%s] %s [%s] %s [%s]",
        aurora.Bold(template.Info.ID),
        aurora.Bold(currentTemplate),
        colorize(severity),
        aurora.Bold(utils.Author(template.Info.Author)),
        aurora.BrightCyan(strings.Join(tagSlice, ", ")))

    log.Info().Msg(logMsg)
}

func Summary(template types.Templates, templates []string) {
    // Print summary information about loaded templates, tags, and keywords
    log.Info().Msgf("Templates have been loaded: %d", len(templates))
    log.Info().Msgf("A total of %d %s have been loaded",
        len(template.Info.Keywords)+len(template.Info.Classification.Tags),
        func() string {
            if len(template.Info.Keywords) > 0 {
                return "keywords"
            }
            return "unique tags"
        }())
    log.Info().Msgf("A total of %d unique matchers have been loaded", len(template.Info.Matchers))

    // Print summary information about loaded TLDs if any have been loaded
    if len(template.Info.Tlds) > 0 {
        log.Info().Msgf("A total of %d TLDs (Top-Level Domains) have been loaded", len(template.Info.Tlds))
    } 
}

func Templates(options types.Options) []Models {
    // Encontrar os templates a serem usados
    templates, _ := template.Find(options.Templates)

    // Slice para armazenar as informações de cada template
    var models []Models
    var template types.Templates

    // Initialize a map to store tags for each loaded YAML
    tagsMap := make(map[string]map[string]bool)
    // Initialize a map to keep track of processed templates
    processed := make(map[string]bool)

    // Ler os arquivos YAML e preencher o slice de Modelss com as informações de cada template
    for _, path := range templates {

        var currentTemplate string

        if err := yaml.ReadYAML(path, &template); err != nil {
            log.Info().Msgf("%s", err)
        }

        // Skip processing if template has already been processed
        if processed[template.Info.ID] {
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

        // Converter os valores de matchers em []string
        var matchersSlice []string
        for _, matcher := range template.Info.Matchers {
            matchersSlice = append(matchersSlice, matcher.Pattern)
        }

        // Converter os valores de tlds em []string
        var tldsSlice []string
        for _, tld := range template.Info.Tlds {
            tldsSlice = append(tldsSlice, tld.Pattern)
        }

        // Adicionar informações do template ao slice de Modelss
        models = append(models, Models{
            Keywords: template.Info.Keywords,
            Matchers: matchersSlice,
            TLDs:     tldsSlice,
            Requests: template.Info.Requests,
            Severity:  template.Info.Severity,
        })

         // Print information about the current template
        tagSlice := make([]string, 0, len(tagsMap[template.Info.ID]))
        for tag := range tagsMap[template.Info.ID] {
            tagSlice = append(tagSlice, tag)
        }

        Info(template, currentTemplate, tagSlice)

        // Mark template as processed
        processed[template.Info.ID] = true
    }

    // Create a slice with unique tags from the tag map
    var tags []string
    for _, tagMap := range tagsMap {
        for tag := range tagMap {
            tags = append(tags, tag)
        }
    }

    // Print summary information about loaded templates, tags, and keywords
    Summary(template, templates)

    // Retornar o slice de TemplateStructs preenchido com as informações de cada template
    return models
}


