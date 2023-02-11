package runner

import (
 "fmt"
 "github.com/projectdiscovery/gologger"
 "pkg/config"
)

var banner = fmt.Sprintf(`
             _             _       _
 ___ ___ ___| |_ _ _ _ ___| |_ ___| |_ ___ ___ 
|  _| -_|  _|  _| | | | .'|  _|  _|   | -_|  _|
|___|___|_| |_| |_____|__,|_| |___|_|_|___|_|  
                                              v%s`, config.Version)

func Banner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\t\t\t%s.io\n\n", config.Name)
}