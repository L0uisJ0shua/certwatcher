package core

import (
    "fmt"
    "internal/colorizer"
    template "pkg/templates"
    "pkg/types"
    "pkg/utils"
    yaml "pkg/yamlreader"
    "strings"

    "github.com/logrusorgru/aurora/v4"
    log "github.com/projectdiscovery/gologger"
)

type Models struct {
    ID       string        `yaml:"id"`
    Keywords []string      `yaml:"keywords"`
    Matchers []string      `yaml:"matchers"`
    TLDs     []string      `yaml:"tlds"`
    Severity string        `yaml:"severity"`
    Requests types.Request `yaml:"requests"`
    Paths    []string
    Status   []int `yaml:"response"`
    Sizes    []int `yaml:"sizes"`
}

type MatcherInfo struct {
    ID       string
    Template string
    Pattern  string
}

var colorize func(interface{}) string

func init() {
    c := colorizer.New()
    colorize = func(s interface{}) string {
        return c(fmt.Sprint(s))
    }
}

func Info(template types.Templates, loadsTags []string) {

    severity := template.Info.Severity

    logMsg := fmt.Sprintf("[%s] %s [%s] %s [%s]",
        aurora.Bold(template.Info.ID),
        aurora.Bold(template.Info.Description),
        colorize(severity),
        aurora.Bold(utils.Author(template.Info.Author)),
        aurora.BrightCyan(strings.Join(loadsTags, ", ")))

    log.Info().Msg(logMsg)
}

func Summary(template types.Templates, matchers []string, loadsTemplates []string) {
    if len(loadsTemplates) > 0 {
        log.Info().Msgf("Templates have been loaded: %d", len(loadsTemplates))
    }
    if len(template.Info.Keywords) > 0 {
        log.Info().Msgf("A total of %d keywords have been loaded", len(template.Info.Keywords))
    }
    if len(template.Info.Classification.Tags) > 0 {
        log.Info().Msgf("A total of %d unique tags have been loaded", len(template.Info.Classification.Tags))
    }
    if len(matchers) > 0 {
        log.Info().Msgf("A total of %d unique matchers have been loaded", len(matchers))
    }
    if len(template.Info.Tlds) > 0 {
        log.Info().Msgf("A total of %d TLDs (Top-Level Domains) have been loaded", len(template.Info.Tlds))
    }
}

func Templates(options types.Options) ([]Models, []string, []string) {
    // Encontrar os templates a serem usados
    templates, _ := template.Find(options.Templates)

    // Slice para armazenar as informações de cada template
    var Templates []Models

    // Slice para armazenar todos os paths de request
    var Path []string
    var Matcher []string

    // Initialize a map to store tags for each loaded YAML
    tagsMap := make(map[string]map[string]bool)
    // Initialize a map to keep track of processed templates
    processed := make(map[string]bool)

    var template types.Templates

    // Ler os arquivos YAML e preencher o slice de Models com as informações de cada template
    for _, path := range templates {

        if err := yaml.ReadYAML(path, &template); err != nil {
            log.Info().Msgf("%s", err)
        }

        // Skip processing if template has already been processed
        if processed[template.Info.ID] {
            continue
        }

        // Append tags to the tag map for the current template
        if _, ok := tagsMap[template.Info.ID]; !ok {
            tagsMap[template.Info.ID] = make(map[string]bool)
        }
        for _, tag := range template.Info.Classification.Tags {
            tagsMap[template.Info.ID][tag] = true
        }

        // Converter os valores de matchers em []string
        for _, matcher := range template.Info.Matchers {
            Matcher = append(Matcher, matcher.Pattern) // Adicionar o path à slice geral
        }
        // Converter os valores de tlds em []string
        var tldsSlice []string
        for _, tld := range template.Info.Tlds {
            tldsSlice = append(tldsSlice, tld.Pattern)
        }

        // Criar um slice para armazenar os caminhos de request do template
        var paths []string
        for _, request := range template.Info.Requests.Path {
            paths = append(paths, request)
            Path = append(Path, request) // Adicionar o path à slice geral
        }

        var statusCodes []int
        for _, response := range template.Info.Response {
            for _, status := range response.Status {
                statusCodes = append(statusCodes, status)
            }
        }

        var SizeCodes []int
        for _, response := range template.Info.Response {
            for _, sizes := range response.Sizes {
                SizeCodes = append(SizeCodes, sizes)
            }
        }

        matchers := make([]string, len(template.Info.Matchers))
        for i, matcher := range template.Info.Matchers {
            matchers[i] = matcher.Pattern
        }

        // Adicionar informações do template ao slice de Models
        Templates = append(Templates, Models{
            ID:       template.Info.ID,
            Keywords: template.Info.Keywords,
            TLDs:     tldsSlice,
            Requests: template.Info.Requests,
            Paths:    Path,
            Severity: template.Info.Severity,
            Status:   statusCodes,
            Sizes:    SizeCodes,
            Matchers: matchers,
        })

        // Marcar o template como processado
        processed[template.Info.ID] = true

        Info(template, template.Info.Classification.Tags)

    }

    // Print summary information about loaded templates, tags, and keywords
    Summary(template, Matcher, templates)

    // Retornar o slice de todas as structs preenchido com as informações de cada template e o slice com todos os paths de requests
    return Templates, Path, Matcher
}
