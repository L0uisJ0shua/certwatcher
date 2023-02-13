package config

import (
	"os"
	"path"
)

func getCurrentDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return dir
}

var (
	// Version represents the current version of the application
	Version = "0.1.0"

	// Name represents the name of the application
	Name = "certwatcher"
	Notice = "\n\nThis project is in active development not ready for production. \nPlease use a proxy to stay safe. Use at your own risk."
	
	Templates = path.Join(getCurrentDirectory(), "internal/app/templates/")
	Keywords = path.Join(getCurrentDirectory(), "internal/app/keywords/fas-keywords-default.yaml")
)