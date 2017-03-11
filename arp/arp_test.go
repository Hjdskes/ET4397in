package arp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecode(t *testing.T) {
	packet := []byte{
		'\x00', '\x01', // HAddress
		'\x08', '\x00', // PAddress
		'\x06',         // HLength
		'\x04',         // PLength
		'\x00', '\x01', // Opcode
		'\x08', '\x9e', '\x01', '\xda', '\x6d', '\xb0', //SHAddress
		'\xc0', '\xa8', '\x00', '\x19', // SPAddress
		'\xff', '\xff', '\xff', '\xff', '\xff', '\xff', // THAddress
		'\xc0', '\xa8', '\x00', '\x0d', // TPAddress
	}

	arp, err := DecodeARP(packet)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(LinkTypeEthernet, arp.HAddress)
	assert.Equal(EtherTypeIPv4, arp.PAddress)
	assert.Equal(uint8(6), arp.HLength)
	assert.Equal(uint8(4), arp.PLength)
	assert.Equal(ARPOpcodeRequest, arp.Opcode)
	assert.Equal([]byte{'\x08', '\x9e', '\x01', '\xda', '\x6d', '\xb0'}, arp.SHAddress)
	assert.Equal([]byte{'\xc0', '\xa8', '\x00', '\x19'}, arp.SPAddress)
	assert.Equal([]byte{'\xff', '\xff', '\xff', '\xff', '\xff', '\xff'}, arp.THAddress)
	assert.Equal([]byte{'\xc0', '\xa8', '\x00', '\x0d'}, arp.TPAddress)
}

func TestDecodeInvalidLinkType(t *testing.T) {
	packet := []byte{
		'\x00', '\x10', // HAddress
		'\x08', '\x00', // PAddress
		'\x06',         // HLength
		'\x04',         // PLength
		'\x00', '\x01', // Opcode
		'\x08', '\x9e', '\x01', '\xda', '\x6d', '\xb0', //SHAddress
		'\xc0', '\xa8', '\x00', '\x19', // SPAddress
		'\xff', '\xff', '\xff', '\xff', '\xff', '\xff', // THAddress
		'\xc0', '\xa8', '\x00', '\x0d', // TPAddress
	}

	_, err := DecodeARP(packet)
	assert.EqualError(t, err, "Link layer protocols other than Ethernet are not supported")
}

func TestDecodeInvalidEtherType(t *testing.T) {
	packet := []byte{
		'\x00', '\x01', // HAddress
		'\x08', '\x11', // PAddress
		'\x06',         // HLength
		'\x04',         // PLength
		'\x00', '\x01', // Opcode
		'\x08', '\x9e', '\x01', '\xda', '\x6d', '\xb0', //SHAddress
		'\xc0', '\xa8', '\x00', '\x19', // SPAddress
		'\xff', '\xff', '\xff', '\xff', '\xff', '\xff', // THAddress
		'\xc0', '\xa8', '\x00', '\x0d', // TPAddress
	}

	_, err := DecodeARP(packet)
	assert.EqualError(t, err, "Ethernet types other than IPv4, ARP and IPv6 are not supported")
}

func TestDecodeInvalidOpcode(t *testing.T) {
	packet := []byte{
		'\x00', '\x01', // HAddress
		'\x08', '\x00', // PAddress
		'\x06',         // HLength
		'\x04',         // PLength
		'\x00', '\x21', // Opcode
		'\x08', '\x9e', '\x01', '\xda', '\x6d', '\xb0', //SHAddress
		'\xc0', '\xa8', '\x00', '\x19', // SPAddress
		'\xff', '\xff', '\xff', '\xff', '\xff', '\xff', // THAddress
		'\xc0', '\xa8', '\x00', '\x0d', // TPAddress
	}

	_, err := DecodeARP(packet)
	assert.EqualError(t, err, "Opcode type should be 1 (REQUEST) or 2 (REPLY)")
}
