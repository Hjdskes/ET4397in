package config

import (
	"encoding/json"
	"io/ioutil"
)

type Configuration struct {
	ARPBindings  map[string][]string `json:"arp-bindings"`
	Interval     int64               `json:"interval"`
	SynInterval  int64               `json:"syn-interval"`
	SynThreshold int32               `json:"syn-threshold"`
	ForwardIP    string              `json:"forward-ip"`
}

func New(configFile string) (*Configuration, error) {
	config := &Configuration{
		ARPBindings:  make(map[string][]string),
		Interval:     1000000000,
		SynInterval:  1000,
		SynThreshold: 1,
		ForwardIP:    "127.0.0.1",
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
