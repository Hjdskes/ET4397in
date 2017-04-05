package module

import (
	"fmt"
	"log"

	"github.com/Hjdskes/ET4397IN/config"
	"github.com/Hjdskes/ET4397IN/dns"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DNSModule struct {
}

func (m DNSModule) Init(config *config.Configuration) error {
	return nil
}

func (m DNSModule) Topics() []string {
	return []string{"packet"}
}

func (m DNSModule) Receive(args []interface{}) bool {
	packet, ok := args[0].(gopacket.Packet)
	if !ok {
		log.Println("DNSModule received data that was not a packet")
		return true
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return true
	}

	data := dnsLayer.LayerContents()
	dns, err := dns.DecodeDNS(data)
	if err != nil {
		log.Println(err)
	} else {
		fmt.Println(dns)
	}

	return true
}
