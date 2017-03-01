package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// DNSOpCode specifies the kind of query.
type DNSOpCode uint8

// DNSOpCode values.
const (
	DNSOpCodeQuery  DNSOpCode = 0 // Query
	DNSOpCodeIQuery DNSOpCode = 1 // Inverse query
	DNSOpCodeStatus DNSOpCode = 2 // Server status
)

// String returns a string representation of the DNSOpCode.
func (code DNSOpCode) String() string {
	switch code {
	case DNSOpCodeQuery:
		return "Query"
	case DNSOpCodeIQuery:
		return "Inverse query"
	case DNSOpCodeStatus:
		return "Status"
	default:
		return "N/A"
	}
}

// DNSRCode specifies the response code.
type DNSRCode uint8

// DNSRCode values.
const (
	DNSRCodeNoError     DNSRCode = 0 // No error
	DNSRCodeFormatError DNSRCode = 1 // Format error
	DNSRCodeServerFail  DNSRCode = 2 // Server failure
	DNSRCodeNameError   DNSRCode = 3 // Name error
	DNSRCodeNotImpl     DNSRCode = 4 // Not implemented
	DNSRCodeRefused     DNSRCode = 5 // Refused
)

// String returns a string representation of the DNSRCode.
func (code DNSRCode) String() string {
	switch code {
	case DNSRCodeNoError:
		return "No error"
	case DNSRCodeFormatError:
		return "Format error"
	case DNSRCodeServerFail:
		return "Server failure"
	case DNSRCodeNameError:
		return "Name error"
	case DNSRCodeNotImpl:
		return "Not implemented"
	case DNSRCodeRefused:
		return "Refused"
	default:
		return "N/A"
	}
}

// From [RFC1035]:
//
// All communications inside of the domain protocol are carried in a single
// format called a message.  The top level format of message is divided
// into 5 sections (some of which are empty in certain cases) shown below:
//
//     +---------------------+
//     |        Header       |
//     +---------------------+
//     |       Question      | the question for the name server
//     +---------------------+
//     |        Answer       | RRs answering the question
//     +---------------------+
//     |      Authority      | RRs pointing toward an authority
//     +---------------------+
//     |      Additional     | RRs holding additional information
//     +---------------------+
//
// The header contains the following fields:
//
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNS contains the data from a single DNS packet.
type DNS struct {
	ID     uint16    // Numeric identifier
	QR     bool      // Is this packet a query (false) or a response (true)?
	OpCode DNSOpCode // The query kind, see DNSOpCode

	AA    bool     // Authorative Answer
	TC    bool     // Truncation
	RD    bool     // Recursion Desired
	RA    bool     // Recursion Available
	Z     uint8    // Reserved for future use
	RCode DNSRCode // Response code, see DNSRCode

	QDCount uint16 // Number of questions
	ANCount uint16 // Number of answers
	NSCount uint16 // Number of authority records
	ARCount uint16 // Number of additional records
}

// DecodeDNS takes a byte slice and attempts to decode the bytes into a DNS
// struct.
func DecodeDNS(data []byte) (*DNS, error) {
	dns := &DNS{}
	err := dns.DecodeFromBytes(data)
	if err != nil {
		return &DNS{}, err
	}
	return dns, nil
}

// DecodeFromBytes takes a byte slice and attempts to decode the bytes into the
// struct it was called on.
func (d *DNS) DecodeFromBytes(data []byte) error {
	// DNS packets have a header of 12 bytes. If the passed byte slice is
	// smaller than that, it is invalid.
	if len(data) < 12 {
		return errors.New("Too small byte slice supplied")
	}
	d.decodeHeader(data[:12])
	return nil
}

func (d *DNS) decodeHeader(data []byte) {
	// ID is 16 bits, so decode the first two bytes from the passed data.
	d.ID = binary.BigEndian.Uint16(data[:2])
	// If bit 16 is 1, QR is true.
	d.QR = data[2]&0x80 != 0
	// Shift the third byte 3 places to the right to get the opcode's value
	// and AND this to set the leftmost four bits to zero.
	d.OpCode = DNSOpCode(data[2]>>3) & 0x0F
	// If bit 21 is 1, AA is true.
	d.AA = data[2]&0x04 != 0
	// If bit 22 is 1, TC is true.
	d.TC = data[2]&0x02 != 0
	// If bit 23 is 1, RD is true.
	d.RD = data[2]&0x01 != 0
	// If bit 24 is 1, RA is true.
	d.RA = data[3]&0x80 != 0
	// Skip the reserved area by setting it to 0.
	d.Z = 0
	// No need to bitshift this time; just get the rcode's value and AND
	// this to set the leftmost four bits to zero.
	d.RCode = DNSRCode(data[3]) & 0x0F

	// Parse the remaining items like we did with ID.
	d.QDCount = binary.BigEndian.Uint16(data[4:6])
	d.ANCount = binary.BigEndian.Uint16(data[6:8])
	d.NSCount = binary.BigEndian.Uint16(data[8:10])
	d.ARCount = binary.BigEndian.Uint16(data[10:12])
}

// String returns a string representation of the DNS struct.
func (d *DNS) String() string {
	return fmt.Sprintf("DNS packet: { ID: %v, QR: %t, OpCode: %v, AA: %t, TC: %t, RD: %t, RA: %t, Z: %v, RCode: %v, QDCount: %v, ANCount: %v, NSCount: %v, ARCount: %v }\n",
		d.ID, d.QR, d.OpCode, d.AA, d.TC, d.RD, d.RA,
		d.Z, d.RCode, d.QDCount, d.ANCount, d.NSCount, d.ARCount)
}
