package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Port         int    `yaml:"port" env:"PORT" env-default:"389"`
	Host         string `yaml:"host" env:"HOST" env-default:"localhost"`
	BindDN       string `yaml:"bindDN" env:"BINDDN" env-default:"cn=Directory Manager"`
	BindPassword string `yaml:"bindPassword" env:"BINDPASSWORD"`
	Usessl       bool   `yaml:"usessl" env:"USESSL" env-default:"false"`
	Starttls     bool   `yaml:"starttls" env:"STARTTLS" env-default:"false"`
}

func GetOptions(fileName string) (Config, error) {
	var cfg Config
	err := cleanenv.ReadConfig(fileName, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
