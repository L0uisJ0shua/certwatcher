package types

// The Templates struct is used to store information about a YAML template, 
// which is used to perform checks in other parts of the code.
type Templates struct {
    Info struct {
        // ID is the unique identifier of the template.
        ID string `yaml:"id"`
        // Name is the name of the template.
        Name string `yaml:"name"`
        // Author is the author of the template.
        Author string `yaml:"author"`
        // Description is the description of the template.
        Description string `yaml:"description"`
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
        Matchers  []struct {
            Pattern     string `yaml:"pattern"`
            Type        string `yaml:"type"`
            Description string `yaml:"description"`
        } `yaml:"matchers"`
        // Tlds is an array of TLD objects, each containing a pattern, type and description.
        Tlds []struct {
            Pattern     string `yaml:"pattern"`
            Type        string `yaml:"type"`
            Description string `yaml:"description"`
        } `yaml:"tlds"`
        // Whitelist contains an array of domains to whitelist and a description of the whitelist type.
        Whitelist struct {
            Domains     []string `yaml:"domains"`
            Type        string   `yaml:"type"`
            Description string   `yaml:"description"`
        } `yaml:"whitelist"`
        // Response specifies the expected response for a match.
        Response []struct {
            StatusCode int `yaml:"status_code"`
        } `yaml:"response"`
    } `yaml:"info"`
}
