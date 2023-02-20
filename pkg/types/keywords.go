package types

type Keywords struct {
	Info struct {
		ID           string `yaml:"id"`
		Name         string `yaml:"name"`
		Author       string `yaml:"author"`
		Description  string `yaml:"description"`
		Classification struct {
			Country string   `yaml:"country"`
			Tags    []string `yaml:"tags"`
		} `yaml:"classification"`
		Keywords []string `yaml:"keywords"`
		Matchers []struct {
			Pattern     string `yaml:"pattern"`
			Type        string `yaml:"type"`
			Description string `yaml:"description"`
		} `yaml:"matchers"`
		Tlds []struct {
			Pattern     string `yaml:"pattern"`
			Type        string `yaml:"type"`
			Description string `yaml:"description"`
		} `yaml:"tlds"`
		Response []struct {
			StatusCode int `yaml:"status_code"`
		} `yaml:"response"`
	}
}
