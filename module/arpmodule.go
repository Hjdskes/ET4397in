package module

import (
	"fmt"
	"log"

	"github.com/Hjdskes/ET4397IN/arp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPModule struct {
}

func (m ARPModule) Topics() []string {
	return []string{"packet"}
}

func (m ARPModule) Receive(args []interface{}) {
	packet, ok := args[0].(gopacket.Packet)
	if !ok {
		log.Println("ARPModule received data that was not a packet")
		return
	}

	if packet.Layer(layers.LayerTypeARP) == nil {
		return
	}

	data := packet.LinkLayer().LayerPayload()
	arp, err := arp.DecodeARP(data)
	if err != nil {
		log.Println(err)
	} else {
		fmt.Println(arp)
	}
}
