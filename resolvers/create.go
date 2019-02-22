package resolvers

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type Resolver struct {
	Nameserver string   `yaml:"nameserver"`
	Ips        []string `yaml:"ips"`
	Ratelimit  int      `yaml:"ratelimit"`
	Enable     bool     `yaml:"enable"`
}

type RetryResolver struct {
	Nameserver string   `yaml:"nameserver"`
	Ips        []string `yaml:"ips"`
	Ratelimit  int      `yaml:"ratelimit"`
	Enable     bool     `yaml:"enable"`
}

type Resolvers struct {
	RetryServers *RetryResolver `yaml:"retry_servers"`
	DnsServers   []*Resolver    `yaml:"resolvers"`
}

func CreateResolversFile() {

	r := Resolvers{}

	r.AddNameservers()

	filename := "resolvers.yaml"

	// Create config file with default modules if it doesn't exist
	if _, err := os.Stat(filename); os.IsNotExist(err) {

		y, err := yaml.Marshal(r)
		if err != nil {
			panic(err)
		}

		f, err := os.Create(filename)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		_, err = f.Write(y)
		if err != nil {
			panic(err)
		}

		fmt.Printf("\nCreated resolvers file: %s\n", filename)
	}
}

func LoadResolvers() *Resolvers {

	var resolvers Resolvers

	filename := "resolvers.yaml"

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	if err := yaml.Unmarshal(b, &resolvers); err != nil {
		panic(err)
	}

	return &resolvers
}
