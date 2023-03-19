package types

// Info contains general information about a template.
type Info struct {
    // ID is the unique identifier of the template.
    ID string `yaml:"id"`
    // Name is the name of the template.
    Name string `yaml:"name"`
    // Author is the author of the template.
    Author string `yaml:"author"`
    // Description is the description of the template.
    Description string `yaml:"description"`
    // Severity Template
    Severity    string `yaml:"severity"`
    // Classification describes the classification of the template, including the country and tags.
    Classification struct {
        Country string   `yaml:"country"`
        Tags    []string `yaml:"tags"`
    } `yaml:"classification"`
    // Condition specifies the condition for the matchers.
    Condition string   `yaml:"matchers-condition"`
    // Keywords specifies the keywords to match.
    Keywords  []string `yaml:"keywords"`
    // Matchers is an array of matcher objects, each containing a pattern, type and description.
    Matchers  []Matcher `yaml:"matchers"`
    // Tlds is an array of TLD objects, each containing a pattern, type and description.
    Tlds []TLD `yaml:"tlds"`
    // Whitelist contains an array of domains to whitelist and a description of the whitelist type.
    Whitelist Whitelist `yaml:"whitelist"`
    // Response specifies the expected response for a match.
    Response []Response `yaml:"response"`
    Requests Request `yaml:"requests"`
}

// Matcher contains a pattern, type, description, and severity.
type Matcher struct {
    Pattern     string `yaml:"pattern"`
    Type        string `yaml:"type"`
    Description string `yaml:"description"`
}

type Request struct {
    Method      string   `yaml:"method"`
    Path        []string `yaml:"path"`
    Description string   `yaml:"description,omitempty"`
    Condition   string   `yaml:"condition,omitempty"`
}

// TLD contains a pattern, type, description, and severity.
type TLD struct {
    Pattern     string `yaml:"pattern"`
    Type        string `yaml:"type"`
    Description string `yaml:"description"`
}

type Whitelist struct {
    Domains     []string `yaml:"domains"`
    Type        string   `yaml:"type"`
    Description string   `yaml:"description"`
}

// Response contains the expected status code for a match.
type Response struct {
    StatusCode int `yaml:"status_code"`
}

// Templates contains information about a YAML template.
type Templates struct {
    Info Info `yaml:"info"`
    Requests Request `yaml:"requests"`
}
