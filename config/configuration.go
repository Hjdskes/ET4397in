package config

import (
	"encoding/json"
	"io/ioutil"
)

type Configuration struct {
	ARPBindings map[string][]string `json:"arp-bindings"`
}

func New(configFile string) (*Configuration, error) {
	file, err := ioutil.ReadFile(configFile)
	if err != nil {
		return &Configuration{}, err
	}

	config := &Configuration{}
	err = json.Unmarshal(file, &config)
	if err != nil {
		return &Configuration{}, err
	}

	//for ip, macs := range config.ARPBindings {
	//	var foo string
	//	for _, mac := range macs {
	//		foo += fmt.Sprintf("%v, ", mac)
	//	}
	//	fmt.Printf("IP: %v with bindings: %v\n", ip, foo)
	//}
	return config, nil
}
