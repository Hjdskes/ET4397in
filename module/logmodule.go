package module

import (
	"fmt"
	"log"

	"github.com/Hjdskes/ET4397IN/config"
)

type LogModule struct {
}

func (m LogModule) Init(config *config.Configuration) error {
	return nil
}

func (m LogModule) Topics() []string {
	return []string{"notice", "error"}
}

func (m LogModule) Receive(args []interface{}) {
	cat, ok := args[0].(string)
	if !ok {
		log.Println("LogModule received data that didn't start with a category")
		cat = "notice"
	}

	msg, ok := args[1].(string)
	if !ok {
		log.Println("LogModule received data that wasn't a valid string")
		return
	}

	switch cat {
	case "notice":
		m.logNotice(msg)
	case "error":
		m.logError(msg)
	}
}

func (m LogModule) logNotice(msg string) {
	fmt.Println("WARNING: ", msg)
}

func (m LogModule) logError(msg string) {
	fmt.Println("ERROR: ", msg)
}
