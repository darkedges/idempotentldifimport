package config

import "flag"

var Flags struct {
	ConfigFN     string
	LdifFN       string
	PrintVersion bool
	Verbose      bool
}

func init() {
	flag.StringVar(&Flags.ConfigFN, "config", "", "Location of configuration file")
	flag.StringVar(&Flags.LdifFN, "ldif", "", "Location of LDIF file")
	flag.BoolVar(&Flags.PrintVersion, "version", false, "Print version.")
	flag.BoolVar(&Flags.Verbose, "verbose", false, "verbose.")
}
