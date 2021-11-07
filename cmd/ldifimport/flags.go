package main

import "flag"

var flags struct {
	configFN     string
	ldifFN       string
	printVersion bool
}

func init() {
	flag.StringVar(&flags.configFN, "config", "", "Location of configuration file")
	flag.StringVar(&flags.ldifFN, "ldif", "", "Location of LDIF file")
	flag.BoolVar(&flags.printVersion, "version", false, "Print version.")
}
