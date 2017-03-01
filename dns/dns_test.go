package dns

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/Hjdskes/ET4397IN/dns"

	"github.com/stretchr/testify/assert"
)

func TestHeader(t *testing.T) {
	// Use the gopacket library to create a DNS packet, that we attempt to
	// parse with our own library below.
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		&layers.DNS{
			ID:           1234,
			QR:           true,
			OpCode:       layers.DNSOpCodeQuery,
			AA:           true,
			TC:           false,
			RD:           true,
			RA:           false,
			Z:            0,
			ResponseCode: layers.DNSResponseCodeNoErr,
			QDCount:      16,
			ANCount:      32,
			NSCount:      48,
			ARCount:      64,
		})

	// Parse the valid DNS packet with our own library.
	d, err := dns.DecodeDNS(buffer.Bytes())
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(d.ID, uint16(1234), "ID should be 1234")
	assert.Equal(d.QR, true, "QR should be true")
	assert.Equal(uint8(d.OpCode), uint8(dns.DNSOpCodeQuery), "OpCode should be Query")
	assert.Equal(d.AA, true, "AA should be true")
	assert.Equal(d.TC, false, "TC should be false")
	assert.Equal(d.RD, true, "RD should be true")
	assert.Equal(d.RA, false, "RA should be false")
	assert.Equal(d.Z, uint8(0), "Z should be 0")
	assert.Equal(uint8(d.RCode), uint8(dns.DNSRCodeNoError), "RCode should be NoError")
	assert.Equal(d.QDCount, uint16(16), "QDCount should be 16")
	assert.Equal(d.ANCount, uint16(32), "ANCount should be 32")
	assert.Equal(d.NSCount, uint16(48), "NSCount should be 48")
	assert.Equal(d.ARCount, uint16(64), "ARCount should be 64")
}
