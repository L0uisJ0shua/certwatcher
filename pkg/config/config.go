package config

import (
	"os"
	"path/filepath"
)

var directory = os.Getenv("HOME")

var (
	// Version represents the current version of the application
	Version = "0.1.0"

	// Name represents the name of the application
	Name   = "certwatcher"
	Notice = "\n\nThis project is in active development not ready for production. \nPlease use a proxy to stay safe. Use at your own risk."

	Templates = filepath.Join(directory, "/.certwatcher-templates", "templates")
	Keywords  = filepath.Join(directory, "/.certwatcher-templates/keywords/", "fas-keywords-default.yaml")
)
