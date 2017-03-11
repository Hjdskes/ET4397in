// The ARP module detects erroneous or noticable conditions in ARP packets. When
// such a condition has been detected, a message is sent to the reporting module
// that will notify the system administrator.
//
// The following conditions are detected:
// 1. Gratuitous ARP replies, notice; TODO
// 2. Hosts trying to bind to the Ethernet broadcast address, error;
// 3. ARP requests that are not sent to the broadcast address, notice;
// 4. ARP replies that are not unicasted to the requester, notice;
// 5. ARP packets that are not internally consistent in that the MAC address of
// the link layer header does not match those in the ARP packet, notice; TODO
package module

import (
	"bytes"
	"fmt"
	"log"

	"github.com/Hjdskes/ET4397IN/arp"
	"github.com/Hjdskes/ET4397IN/hub"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPModule struct {
	Hub *hub.Hub
}

func (m ARPModule) Protos() []string {
	return []string{"arp"}
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
		m.Hub.Publish("error", err.Error())
	} else {
		m.analyse(arp)
	}
}

func (m ARPModule) analyse(a *arp.ARP) {
	var cat string
	var msg string

	switch a.Opcode {
	case arp.ARPOpcodeRequest:
		if bytes.Equal(a.THAddress, arp.BroadcastAddress) {
			cat = "notice"
			msg = fmt.Sprintf("Host %v is unicasting an ARP request to %v", a.SPAddress, a.TPAddress)
		} else if bytes.Equal(a.SPAddress, a.TPAddress) && bytes.Equal(a.THAddress, arp.BroadcastAddress) {
			cat = "notice"
			msg = fmt.Sprintf("Host %v sent a gratuitous request", a.SPAddress)
		}
	case arp.ARPOpcodeReply:
		if bytes.Equal(a.SHAddress, arp.BroadcastAddress) {
			cat = "error"
			msg = fmt.Sprintf("Host %v is trying to bind to the Ethernet broadcast address", a.SPAddress)
		} else if bytes.Equal(a.TPAddress, arp.BroadcastAddress) {
			cat = "notice"
			msg = fmt.Sprintf("Host %v is replying to a request from host %v using a broadcast message", a.SPAddress, a.TPAddress)
		} else if bytes.Equal(a.SPAddress, a.TPAddress) && bytes.Equal(a.THAddress, arp.BroadcastAddress) {
			cat = "notice"
			msg = fmt.Sprintf("Host %v sent a gratuitous reply", a.SPAddress)
		}
	}

	if cat != "" && msg != "" {
		m.Hub.Publish(cat, msg)
	}
}
