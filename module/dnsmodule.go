package module

import (
	"fmt"
	"log"

	"github.com/Hjdskes/ET4397IN/dns"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DNSModule struct {
}

func (m DNSModule) LayerType() gopacket.LayerType {
	return layers.LayerTypeDNS
}

func (m DNSModule) Process(data []byte) {
	dns, err := dns.DecodeDNS(data)
	if err != nil {
		log.Println(err)
	} else {
		fmt.Println(dns)
	}
}
