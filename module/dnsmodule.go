package module

import (
	"errors"
	"fmt"
	"log"

	"github.com/Hjdskes/ET4397IN/dns"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DNSModule struct {
}

func (m DNSModule) Topics() []string {
	return []string{"packet"}
}

func (m DNSModule) Process(args []interface{}) {
	packet, ok := args[0].(gopacket.Packet)
	if !ok {
		log.Println("DNSModule received data that was not a packet")
		return
	}

	data, err := extractPayload(packet)
	if err != nil {
		// Silently ignore, otherwise we get spammed for every packet.
		return
	}

	dns, err := dns.DecodeDNS(data)
	if err != nil {
		log.Println(err)
	} else {
		fmt.Println(dns)
	}
}

func extractPayload(packet gopacket.Packet) ([]byte, error) {
	if packet.Layer(layers.LayerTypeDNS) != nil {
		return packet.TransportLayer().LayerPayload(), nil
	}

	return nil, errors.New("Packet does not contain a DNS message to extract")
}
