package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

const (
	configFile = "config.yaml"
)

type Config struct {
	MaximumDnsServers int `yaml:"maximum_dns_servers"`
}

func CreateConfig() bool {

	c := Config{}

	c.MaximumDnsServers = 0

	// Create config file if it doesn't exist
	if _, err := os.Stat(configFile); os.IsNotExist(err) {

		y, err := yaml.Marshal(c)
		if err != nil {
			panic(err)
		}

		f, err := os.Create(configFile)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		_, err = f.Write(y)
		if err != nil {
			panic(err)
		}

		fmt.Printf("\nCreated %s\n", configFile)

		return true
	}

	return false
}

func LoadConfig() *Config {

	var c Config

	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		panic(err)
	}

	if err := yaml.Unmarshal(b, &c); err != nil {
		panic(err)
	}

	return &c
}
