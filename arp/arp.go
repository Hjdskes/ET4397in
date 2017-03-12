package arp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var (
	BroadcastAddress = []byte{'\xff', '\xff', '\xff', '\xff', '\xff', '\xff'}
)

// ARPOpcode is a two byte field that specifies the kind of ARP packet.
type ARPOpcode uint16

// ARPOpcode values.
const (
	ARPOpcodeRequest ARPOpcode = 1 // Request
	ARPOpcodeReply   ARPOpcode = 2 // Reply
)

// String returns a string representation of the ARPOpcode.
func (code ARPOpcode) String() string {
	switch code {
	case ARPOpcodeRequest:
		return "Request"
	case ARPOpcodeReply:
		return "Reply"
	default:
		return "N/A"
	}
}

// LinkType is a one byte value to encode different kinds of link layer
// protocols.
type LinkType uint8

// LinkType values.
const (
	LinkTypeEthernet LinkType = 1 // Ethernet
)

// String returns a string representation of the LinkType.
func (t LinkType) String() string {
	switch t {
	case LinkTypeEthernet:
		return "Ethernet"
	default:
		return "N/A"
	}
}

// EtherType is a two byte value to encode which protocol is encapsulated in an
// Ethernet frame.
type EtherType uint16

// EtherType values.
const (
	EtherTypeIPv4 EtherType = 0x0800 // IPv4
	EtherTypeARP  EtherType = 0x0806 // ARP
	EtherTypeIPv6 EtherType = 0x86DD // IPv6
)

// String returns a string representation of the EtherType.
func (t EtherType) String() string {
	switch t {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeIPv6:
		return "IPv6"
	default:
		return "N/A"
	}
}

// ARP contains the data from a single ARP packet. Note that currently only the
// Ethernet protocol is supported.
//
// From RFC826:
//
//     Ethernet transmission layer (not necessarily accessible to the user):
//	48.bit: Ethernet address of destination
//	48.bit: Ethernet address of sender
//	16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION
//    Ethernet packet data:
//	16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
//			 Packet Radio Net.)
//	16.bit: (ar$pro) Protocol address space.  For Ethernet
//			 hardware, this is from the set of type
//			 fields ether_typ$<protocol>.
//	 8.bit: (ar$hln) byte length of each hardware address
//	 8.bit: (ar$pln) byte length of each protocol address
//	16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
//	nbytes: (ar$sha) Hardware address of sender of this
//			 packet, n from the ar$hln field.
//	mbytes: (ar$spa) Protocol address of sender of this
//			 packet, m from the ar$pln field.
//	nbytes: (ar$tha) Hardware address of target of this
//			 packet (if known).
//	mbytes: (ar$tpa) Protocol address of target.
//
type ARP struct {
	HAddress  LinkType  // Hardware address space, see LinkType
	PAddress  EtherType // Protocol address space, see EtherType
	HLength   uint8     // Byte length of each hardware address
	PLength   uint8     // Byte length of each protocol address
	Opcode    ARPOpcode // Opcode, see ARPOpcode
	SHAddress []byte    // Hardware address of sender
	SPAddress []byte    // Protocol address of sender
	THAddress []byte    // Hardware address of target
	TPAddress []byte    // Protocol address of target
}

// DecodeARP takes a byte slice and attempts to decode the bytes into an ARP
// struct.
func DecodeARP(data []byte) (*ARP, error) {
	arp := &ARP{}
	err := arp.decode(data)
	if err != nil {
		return &ARP{}, err
	}
	return arp, nil
}

func (a *ARP) decode(data []byte) error {
	a.HAddress = LinkType(binary.BigEndian.Uint16(data[0:2]))
	if a.HAddress != LinkTypeEthernet {
		return errors.New("Link layer protocols other than Ethernet are not supported")
	}
	a.PAddress = EtherType(binary.BigEndian.Uint16(data[2:4]))
	switch a.PAddress {
	case EtherTypeIPv4, EtherTypeIPv6, EtherTypeARP:
		break
	default:
		return errors.New("Ethernet types other than IPv4, ARP and IPv6 are not supported")
	}
	a.HLength = data[4]
	a.PLength = data[5]
	a.Opcode = ARPOpcode(binary.BigEndian.Uint16(data[6:8]))
	switch a.Opcode {
	case ARPOpcodeRequest, ARPOpcodeReply:
		break
	default:
		return errors.New("Opcode type should be 1 (REQUEST) or 2 (REPLY)")
	}
	a.SHAddress = data[8 : 8+a.HLength]
	a.SPAddress = data[8+a.HLength : 8+a.HLength+a.PLength]
	a.THAddress = data[8+a.HLength+a.PLength : 8+2*a.HLength+a.PLength]
	a.TPAddress = data[8+2*a.HLength+a.PLength : 8+2*a.HLength+2*a.PLength]
	return nil
}

func (a *ARP) IsUnicastRequest() bool {
	return !bytes.Equal(a.THAddress, BroadcastAddress)
}

func (a *ARP) IsGratuitous() bool {
	return bytes.Equal(a.SPAddress, a.TPAddress) &&
		bytes.Equal(a.THAddress, BroadcastAddress)
}

func (a *ARP) IsBindingEthernet() bool {
	return bytes.Equal(a.SHAddress, BroadcastAddress)
}

func (a *ARP) IsBroadcastReply() bool {
	return bytes.Equal(a.TPAddress, BroadcastAddress)
}
