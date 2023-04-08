package runner

import (
	"fmt"
	"pkg/config"

	"github.com/projectdiscovery/gologger"
)

func ShowBanner() error {
	// Carrega as informações de configuração
	appConfig, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	banner := fmt.Sprintf(`
             _             _       _
 ___ ___ ___| |_ _ _ _ ___| |_ ___| |_ ___ ___ 
|  _| -_|  _|  _| | | | .'|  _|  _|   | -_|  _|
|___|___|_| |_| |_____|__,|_| |___|_|_|___|_|  
                                              v%s%s`, appConfig.Version, appConfig.Notice)

	gologger.Print().Msgf("%s\n\n", banner)
	gologger.Print().Msgf("\t\t%s.io\n\n", appConfig.Name)

	return nil
}