package runner

import (
 "fmt"
 "github.com/projectdiscovery/gologger"
 "pkg/config"
)

var sBanner = fmt.Sprintf(`
             _             _       _
 ___ ___ ___| |_ _ _ _ ___| |_ ___| |_ ___ ___ 
|  _| -_|  _|  _| | | | .'|  _|  _|   | -_|  _|
|___|___|_| |_| |_____|__,|_| |___|_|_|___|_|  
                                              v%s%s`, config.Version, config.Notice)

func Banner() {
	gologger.Print().Msgf("%s\n\n", sBanner)
	gologger.Print().Msgf("\t\t%s.io\n\n", config.Name)
}