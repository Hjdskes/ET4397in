package dns

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/stretchr/testify/assert"
)

func TestDecodeNameValid(t *testing.T) {
	name := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'}
	res, offset, err := decodeDomainName(name, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(len(name), offset, "Offset should point one byte past the length of the octets in `name`")
	assert.Equal("google.com", res, "The name should be google.com")
}

func TestDecodeNameOffsetTooLarge(t *testing.T) {
	name := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'}
	res, offset, err := decodeDomainName(name, 12)

	assert := assert.New(t)
	assert.Equal(0, offset, "Offset should be set to zero")
	assert.Equal("", res, "Result should be the empty string")
	assert.EqualError(err, "Offset too large", "A too large offset should return an error")
}

func TestDecodeNameZeroOctet(t *testing.T) {
	name := []byte{'\x00'}
	res, offset, err := decodeDomainName(name, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(1, offset, "Offset should be incremented by one")
	assert.Equal("", res, "Result should be the empty string")
}

func TestDecodePointerValid(t *testing.T) {
	name := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', '\xc0', '\x00'}
	res, offset, err := decodeDomainName(name, 12)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(14, offset, "Offset should point two bytes past the length of the passed-in offset")
	assert.Equal("google.com", res, "The name should be google.com")
}

func TestDecodePointerIncomplete(t *testing.T) {
	name := []byte{'\xc0'}
	res, offset, err := decodeDomainName(name, 0)

	assert := assert.New(t)
	assert.Equal(0, offset, "Offset should be set to zero")
	assert.Equal("", res, "Result should be the empty string")
	assert.EqualError(err, "Name pointer incomplete", "A name pointer should be two octets long")
}

func TestDecodePointerTooLarge(t *testing.T) {
	name := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', '\xcf', '\xff'}
	res, offset, err := decodeDomainName(name, 12)

	assert := assert.New(t)
	assert.Equal(0, offset, "Offset should be set to zero")
	assert.Equal("", res, "Result should be the empty string")
	assert.EqualError(err, "Offset too large", "The offset pointer should point to valid data")
}

func TestDecodeNameLengthTooLong(t *testing.T) {
	name := []byte{'\x3f', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'}
	res, offset, err := decodeDomainName(name, 0)

	assert := assert.New(t)
	assert.Equal(0, offset, "Offset should be set to zero")
	assert.Equal("", res, "Result should be the empty string")
	assert.EqualError(err, "Label length too long", "A name can't be more than 255 octets")
}

func TestDecodeCharacterStrings(t *testing.T) {
	strings := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm'}
	res, err := decodeCharacterStrings(strings)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(2, len(res), "The result should contain two strings")
	assert.Equal("google", res[0], "The first string should be google")
	assert.Equal("com", res[1], "The second string should be com")
}

func TestDecodeCharacterStringsLengthTooLong(t *testing.T) {
	strings := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x04', 'c', 'o', 'm'}
	res, err := decodeCharacterStrings(strings)

	assert := assert.New(t)
	assert.Equal(0, len(res), "The result should be empty")
	assert.EqualError(err, "Character string length too long", "The length cannot point outside the data")
}

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
			QDCount:      4,
			ANCount:      8,
			NSCount:      16,
			ARCount:      32,
		})
	// Parse the valid DNS packet with our own library.
	h := DNSHeader{}
	_, err := h.decode(buffer.Bytes(), 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(uint16(1234), h.ID, "ID should be 1234")
	assert.Equal(true, h.QR, "QR should be true")
	assert.Equal(uint8(DNSOpcodeQuery), uint8(h.Opcode), "Opcode should be Query")
	assert.Equal(true, h.AA, "AA should be true")
	assert.Equal(false, h.TC, "TC should be false")
	assert.Equal(true, h.RD, "RD should be true")
	assert.Equal(false, h.RA, "RA should be false")
	assert.Equal(uint8(0), h.Z, "Z should be 0")
	assert.Equal(uint8(DNSRCodeNoError), uint8(h.RCode), "RCode should be NoError")
	assert.Equal(uint16(4), h.QDCount, "QDCount should be 4")
	assert.Equal(uint16(8), h.ANCount, "ANCount should be 8")
	assert.Equal(uint16(16), h.NSCount, "NSCount should be 16")
	assert.Equal(uint16(32), h.ARCount, "ARCount should be 32")
}

func TestQuestion(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', '\x00', '\x01', '\x00', '\x01'}

	q := DNSQuestion{}
	offset, err := q.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal(len(data), offset, "Offset should point to after the Question")
	assert.Equal("google.com", q.QName, "Name should be google.com")
	assert.Equal(DNSTypeA, q.QType, "DNSType should be A")
	assert.Equal(DNSClassIN, q.QClass, "DNSClass should be IN")
}

func TestResource(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x01', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x04', // RDLENGTH
		'\xc0', '\xa8', '\x00', '\x01'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypeA, r.Type, "DNSType should be A")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(4), r.RDLength, "RDLength should be 4")
	assert.Equal(net.ParseIP("192.168.0.1")[12:16], r.Address, "RData should be the IP address 192.168.0.1")
	assert.Equal(len(data), offset, "Offset should point past the data")
}

func TestResourceLengthTooLong(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x01', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x05', // RDLENGTH
		'\xc0', '\xa8', '\x00', '\x01'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)

	assert := assert.New(t)
	assert.Equal(0, offset, "Offset should be set to 0")
	assert.EqualError(err, "Resource length is longer than the message length", "The resource length cannot be too long")
}

func TestResourceNS(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x02', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x0c', // RDLENGTH
		'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypeNS, r.Type, "DNSType should be NS")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(12), r.RDLength, "RDLength should be 12")
	assert.Equal("google.com", r.NSDName, "RDATA should be google.com")
	assert.Equal(len(data), offset, "Offset should point past the data")
}

func TestResourceCName(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x05', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x0c', // RDLENGTH
		'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypeCName, r.Type, "DNSType should be CName")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(12), r.RDLength, "RDLength should be 12")
	assert.Equal("google.com", r.CName, "RDATA should be google.com")
	assert.Equal(len(data), offset, "Offset should point past the data")
}

func TestResourceSOA(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x06', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x2C', // RDLENGTH
		'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // MName
		'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // RName
		'\x00', '\x00', '\xff', '\xff', // Serial
		'\x00', '\x00', '\xff', '\xff', // Refresh
		'\x00', '\x00', '\xff', '\xff', // Retry
		'\x00', '\x00', '\xff', '\xff', // Expire
		'\x00', '\x00', '\xff', '\xff'} // Minimum

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypeSOA, r.Type, "DNSType should be SOA")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(44), r.RDLength, "RDLength should be 44")
	assert.Equal("google.com", r.MName, "MName should be google.com")
	assert.Equal("google.com", r.RName, "RName should be google.com")
	assert.Equal(uint32(65535), r.Serial, "Serial should be 65535")
	assert.Equal(uint32(65535), r.Refresh, "Refresh should be 65535")
	assert.Equal(uint32(65535), r.Retry, "Retry should be 65535")
	assert.Equal(uint32(65535), r.Expire, "Expire should be 65535")
	assert.Equal(uint32(65535), r.Minimum, "Minimum should be 65535")
	assert.Equal(len(data), offset, "Offset should point past the data")
}

func TestResourcePTR(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x0c', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x0c', // RDLENGTH
		'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypePTR, r.Type, "DNSType should be PTR")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(12), r.RDLength, "RDLength should be 12")
	assert.Equal("google.com", r.PTRDName, "RDATA should be google.com")
	assert.Equal(len(data), offset, "Offset should point past the data")
}

func TestResourceMX(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x0f', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x0e', // RDLENGTH
		'\xca', '\x23', '\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypeMX, r.Type, "DNSType should be MX")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(14), r.RDLength, "RDLength should be 14")
	assert.Equal(uint16(51747), r.Preference, "Preference should be ")
	assert.Equal("google.com", r.Exchange, "Exchange should be google.com")
	assert.Equal(len(data), offset, "Offset should point past the data")
}

func TestResourceTXT(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x10', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x0b', // RDLENGTH
		'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypeTXT, r.Type, "DNSType should be TXT")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(11), r.RDLength, "RDLength should be 11")
	assert.Equal([]string{"google", "com"}, r.TXT, "RData should be the strings google and com")
	assert.Equal(len(data), offset, "Offset should point past the data")
}

func TestResourceUnknown(t *testing.T) {
	data := []byte{'\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00', // NAME
		'\x00', '\x0a', // TYPE
		'\x00', '\x01', // CLASS
		'\x00', '\x00', '\xff', '\xff', // TTL
		'\x00', '\x01', // RDLENGTH
		'a'} // RDATA

	r := DNSResource{}
	offset, err := r.decode(data, 0)
	if err != nil {
		t.Error(err)
	}

	assert := assert.New(t)
	assert.Equal("google.com", r.Name, "Name should be google.com")
	assert.Equal(DNSTypeNull, r.Type, "DNSType should be NULL")
	assert.Equal(DNSClassIN, r.Class, "DNSClass should be IN")
	assert.Equal(uint32(65535), r.TTL, "TTL should be 65535")
	assert.Equal(uint16(1), r.RDLength, "RDLength should be 1")
	assert.Equal([]byte{'a'}, r.RData, "RData should be 'a'")
	assert.Equal(len(data), offset, "Offset should point past the data")
}
