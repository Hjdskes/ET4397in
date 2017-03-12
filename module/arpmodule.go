// The ARP module detects erroneous or noticable conditions in ARP packets. When
// such a condition has been detected, a message is sent to the reporting module
// that will notify the system administrator.
//
// The following conditions are detected:
// 1. Gratuitous ARP requests and replies, notice;
// 2. Hosts trying to bind to the Ethernet broadcast address, error;
// 3. ARP requests that are not sent to the broadcast address, notice;
// 4. ARP replies that are not unicasted to the requester, notice;
// 5. ARP packets that are not internally consistent in that the MAC address of
// the link layer header does not match those in the ARP packet, notice; TODO
// 6. ARP replies with an IP-to-MAC allocation that is not found in the
// configuration.
package module

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/Hjdskes/ET4397IN/arp"
	"github.com/Hjdskes/ET4397IN/config"
	"github.com/Hjdskes/ET4397IN/hub"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPModule struct {
	Hub *hub.Hub

	// A map of valid IP-to-MAC allocations, where the IP address is stored
	// as a string because a byte slice cannot be used as a key, see
	// http://stackoverflow.com/a/39249045. The MAC address is encoded using
	// a slice of bytes. Note the [][]byte means a list of byte slices, and
	// hence that one IP address may be allocated to more than one MAC
	// address (in e.g. failover setups).
	validBindings map[string][][]byte
}

func (m ARPModule) Init(config *config.Configuration) error {
	m.validBindings = make(map[string][][]byte)

	for ip, macs := range config.ARPBindings {
		for _, s := range macs {
			mac, err := net.ParseMAC(s)
			if err != nil {
				log.Println("Invalid MAC address found in configuration: ", s)
			} else {
				m.validBindings[ip] = append(m.validBindings[ip], mac)
			}
		}
	}

	return nil
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

const (
	unicastRequest = "Host %v is unicasting an ARP request to host %v"
	gratuitous     = "Host %v sent a gratuitous %v"
	bindEthernet   = "Host %v is trying to bind to the Ethernet broadcast address"
	broadcastReply = "Host %v is replying to a request from host %v using a broadcast message"
	invalidBinding = "Host %v is trying to bind to MAC address %v that is not in the list"
)

func (m ARPModule) analyse(a *arp.ARP) {
	var cat string
	var msg string

	switch a.Opcode {
	case arp.ARPOpcodeRequest:
		if a.IsGratuitous() {
			cat = "notice"
			msg = fmt.Sprintf(gratuitous, a.SPAddress, a.Opcode)
		} else if a.IsUnicastRequest() {
			cat = "notice"
			msg = fmt.Sprintf(unicastRequest, a.SPAddress, a.TPAddress)
		}
	case arp.ARPOpcodeReply:
		if a.IsBindingEthernet() {
			cat = "error"
			msg = fmt.Sprintf(bindEthernet, a.SPAddress)
		} else if a.IsBroadcastReply() {
			cat = "notice"
			msg = fmt.Sprintf(broadcastReply, a.SPAddress, a.TPAddress)
		} else if a.IsGratuitous() {
			cat = "notice"
			msg = fmt.Sprintf(gratuitous, a.SPAddress, a.Opcode)
		} else if !m.isValidBinding(a) {
			cat = "notice"
			msg = fmt.Sprintf(invalidBinding, a.SPAddress, a.SHAddress)
		}
	}

	if cat != "" && msg != "" {
		m.Hub.Publish("log", cat, msg)
	}
}

func (m ARPModule) isValidBinding(a *arp.ARP) bool {
	// Retrieve the list of allowed MAC addresses for this IP address.
	// Note: converting the IP address to a string here is kind of ugly,
	// since bytes of an IP address may not be valid UTF-8 strings (which is
	// how Go stores strings), but string values represent arbitrary byte
	// sequences so this works while being much simpler and more efficient,
	// see http://stackoverflow.com/a/39249045
	macs := m.validBindings[string(a.SPAddress)]

	// If any MAC addresses are found, then check if the one in the packet
	// is among them.
	if len(macs) > 0 {
		for _, mac := range macs {
			// As soon as a MAC address matches, we know a valid
			// binding is found and we can return true.
			if bytes.Equal(mac, a.SHAddress) {
				return true
			}
		}
	}

	// This is only reached if there is no valid IP-to-MAC binding for this
	// packet, so we return false.
	return false
}
