package runner

import (
	"fmt"
	"pkg/config"

	"github.com/projectdiscovery/gologger"
)

var banner = fmt.Sprintf(`
             _             _       _
 ___ ___ ___| |_ _ _ _ ___| |_ ___| |_ ___ ___ 
|  _| -_|  _|  _| | | | .'|  _|  _|   | -_|  _|
|___|___|_| |_| |_____|__,|_| |___|_|_|___|_|  
                                              v%s%s`, config.Version, config.Notice)

func ShowBanner() {
	gologger.Print().Msgf("%s\n\n", banner)
	gologger.Print().Msgf("\t\t%s.io\n\n", config.Name)
}
