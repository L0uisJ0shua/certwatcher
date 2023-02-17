package runner

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"pkg/config"
)

var well = fmt.Sprintf(`
             _             _       _
 ___ ___ ___| |_ _ _ _ ___| |_ ___| |_ ___ ___ 
|  _| -_|  _|  _| | | | .'|  _|  _|   | -_|  _|
|___|___|_| |_| |_____|__,|_| |___|_|_|___|_|  
                                              v%s%s`, config.Version, config.Notice)

func Welcome() {
	gologger.Print().Msgf("%s\n\n", well)
	gologger.Print().Msgf("\t\t%s.io\n\n", config.Name)
}
