package config

import (
	"encoding/json"
	"io/ioutil"
)

type Configuration struct {
	ARPBindings map[string][]string `json:"arp-bindings"`
	Interval    int64               `json:"interval"`
}

func New(configFile string) (*Configuration, error) {
	config := &Configuration{
		ARPBindings: make(map[string][]string),
		Interval:    1000,
	}

	file, err := ioutil.ReadFile(configFile)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(file, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
