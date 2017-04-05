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
	return []string{"log"}
}

func (m LogModule) Receive(args []interface{}) bool {
	if len(args) != 2 {
		log.Println("LogModule needs a category and a message")
		return true
	}

	cat, ok := args[0].(string)
	if !ok {
		log.Println("LogModule category should be a string, defaulting to notice")
		cat = "notice"
	}

	msg, ok := args[1].(string)
	if !ok {
		log.Println("LogModule message should be a string, aborting")
		return true
	}

	switch cat {
	case "notice":
		m.logNotice(msg)
	case "error":
		m.logError(msg)
	}

	return true
}

func (m LogModule) logNotice(msg string) {
	fmt.Println("WARNING: ", msg)
}

func (m LogModule) logError(msg string) {
	fmt.Println("ERROR: ", msg)
}
