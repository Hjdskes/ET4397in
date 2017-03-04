package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// RFC1035:
//
// Opcode is a four bit field that specifies the kind of query in this
// message.
type DNSOpcode uint8

// DNSOpcode values.
const (
	DNSOpcodeQuery  DNSOpcode = 0 // Standard query
	DNSOpcodeIQuery DNSOpcode = 1 // Inverse query
	DNSOpcodeStatus DNSOpcode = 2 // Server status request
)

// String returns a string representation of the DNSOpcode.
func (code DNSOpcode) String() string {
	switch code {
	case DNSOpcodeQuery:
		return "Query"
	case DNSOpcodeIQuery:
		return "Inverse query"
	case DNSOpcodeStatus:
		return "Status"
	default:
		return "N/A"
	}
}

// RFC1035:
//
// RCode is a 4 bit field set as part of responses.
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

// DNSType specifies the TYPE and QTYPE values of a question or response.
//
// RFC1035:
//
// QTYPE fields appear in the question part of a query.  QTYPES are a
// superset of TYPEs, hence all TYPEs are valid QTYPEs.
// TYPE fields are used in resource records.  Note that these types are a
// subset of QTYPEs.
type DNSType uint16

// DNSType values.
const (
	DNSTypeA     DNSType = 1   // Host address
	DNSTypeNS    DNSType = 2   // Authorative name server
	DNSTypeMD    DNSType = 3   // Mail destination (Obsolete - use MX)
	DNSTypeMF    DNSType = 4   // Mail forwarder (Obsolete - use MX)
	DNSTypeCName DNSType = 5   // Canonical name for an alias
	DNSTypeSOA   DNSType = 6   // Start of a zone authority
	DNSTypeMB    DNSType = 7   // Mailbox domain name (EXPERIMENTAL)
	DNSTypeMG    DNSType = 8   // Mail group member (EXPERIMENTAL)
	DNSTypeMR    DNSType = 9   // Mail rename domain name (EXPERIMENTAL)
	DNSTypeNull  DNSType = 10  // Null RR (EXPERIMENTAL)
	DNSTypeWKS   DNSType = 11  // Well known service description
	DNSTypePTR   DNSType = 12  // Domain name pointer
	DNSTypeHInfo DNSType = 13  // Host information
	DNSTypeMInfo DNSType = 14  // Mailbox or mail list information
	DNSTypeMX    DNSType = 15  // Mail exchange
	DNSTypeTXT   DNSType = 16  // Text strings
	DNSTypeAXFR  DNSType = 252 // Request for transfer of an entire zone
	DNSTypeMailB DNSType = 253 // Request for mailbox-related records (MB, MG or MR)
	DNSTypeMailA DNSType = 254 // Request for mail agent RRs (Obsolete - see MX)
	DNSTypeStar  DNSType = 255 // Request all records
)

// String returns a string representation of the DNSType.
func (t DNSType) String() string {
	switch t {
	case DNSTypeA:
		return "A"
	case DNSTypeNS:
		return "NS"
	case DNSTypeMD:
		return "MD"
	case DNSTypeMF:
		return "MF"
	case DNSTypeCName:
		return "CName"
	case DNSTypeSOA:
		return "SOA"
	case DNSTypeMB:
		return "MB"
	case DNSTypeMG:
		return "MG"
	case DNSTypeMR:
		return "MR"
	case DNSTypeNull:
		return "Null"
	case DNSTypeWKS:
		return "WKS"
	case DNSTypePTR:
		return "PTR"
	case DNSTypeHInfo:
		return "HInfo"
	case DNSTypeMInfo:
		return "MInfo"
	case DNSTypeMX:
		return "MX"
	case DNSTypeTXT:
		return "TXT"
	case DNSTypeAXFR:
		return "AXFR"
	case DNSTypeMailB:
		return "MailB"
	case DNSTypeMailA:
		return "MailA"
	case DNSTypeStar:
		return "*"
	default:
		return "N/A"
	}
}

// DNSClass specifies the class of a question or response.
//
// RFC1035:
//
// CLASS fields appear in resource records.
// QCLASS fields appear in the question section of a query. QCLASS values are a
// superset of CLASS values.
type DNSClass uint16

// DNSClass values.
const (
	DNSClassIN   DNSClass = 1   // Internet
	DNSClassCS   DNSClass = 2   // CSNET (Obsolete)
	DNSClassCH   DNSClass = 3   // CHAOS
	DNSClassHS   DNSClass = 4   // Hesiod
	DNSClassStar DNSClass = 255 // Any class
)

// String returns a string representation of the DNSClass.
func (class DNSClass) String() string {
	switch class {
	case DNSClassIN:
		return "IN"
	case DNSClassCS:
		return "CS"
	case DNSClassCH:
		return "CH"
	case DNSClassHS:
		return "HS"
	case DNSClassStar:
		return "*"
	default:
		return "N/A"
	}
}

// DNSHeader contains the data from a single DNS header.
//
// From RFC1035:
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
type DNSHeader struct {
	ID      uint16    // Identifier
	QR      bool      // Is this message a query (false) or a response (true)?
	Opcode  DNSOpcode // The query kind, see DNSOpcode
	AA      bool      // Authorative Answer
	TC      bool      // TrunCation
	RD      bool      // Recursion Desired
	RA      bool      // Recursion Available
	Z       uint8     // Reserved for future use
	RCode   DNSRCode  // Response code, see DNSRCode
	QDCount uint16    // Number of questions
	ANCount uint16    // Number of answers
	NSCount uint16    // Number of authority records
	ARCount uint16    // Number of additional records
}

func (h *DNSHeader) decode(data []byte, offset int) (int, error) {
	// ID is 16 bits, so decode the first two bytes from the passed data.
	h.ID = binary.BigEndian.Uint16(data[:2])
	// If bit 16 is 1, QR is true.
	h.QR = data[2]&0x80 != 0
	// Shift the third byte 3 places to the right to get the opcode's value
	// and AND this to set the leftmost four bits to zero.
	h.Opcode = DNSOpcode((data[2] >> 3) & 0x0f)
	// If bit 21 is 1, AA is true.
	h.AA = data[2]&0x04 != 0
	// If bit 22 is 1, TC is true.
	h.TC = data[2]&0x02 != 0
	// If bit 23 is 1, RD is true.
	h.RD = data[2]&0x01 != 0
	// If bit 24 is 1, RA is true.
	h.RA = data[3]&0x80 != 0
	// Skip the reserved area by setting it to 0.
	h.Z = 0
	// No need to bitshift this time; just get the rcode's value and AND
	// this to set the leftmost four bits to zero.
	h.RCode = DNSRCode(data[3] & 0x0f)

	// Parse the remaining items like we did with ID.
	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ARCount = binary.BigEndian.Uint16(data[10:12])

	return 12, nil
}

// DNSQuestion contains the data from a single DNS question.
//
// RFC1035:
//
// The question section is used to carry the "question" in most queries, i.e.,
// the parameters that define what is being asked.  The section contains QDCOUNT
// (usually 1) entries, each of the following format:
//
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                     QNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QTYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QCLASS                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type DNSQuestion struct {
	QName  string   // Domain name
	QType  DNSType  // Type of query, see DNSType
	QClass DNSClass // Class of query, see DNSClass
}

func (q *DNSQuestion) decode(data []byte, offset int) (int, error) {
	// Decode the variable length domain name, that starts at the offset we
	// are given. It returns the decoded domain name and the offset from
	// which we should continue decoding this question if there is no error;
	// otherwise it returns an error and we cannot continue decoding this
	// DNS message.
	name, offset, err := decodeDomainName(data, offset)
	if err != nil {
		return 0, err
	}

	q.QName = name
	// QType is 16 bits, so decode the first two bytes from the offset.
	q.QType = DNSType(binary.BigEndian.Uint16(data[offset : offset+2]))
	// QClass is 16 bits, so decode the second two bytes from the offset.
	q.QClass = DNSClass(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	return offset + 4, nil
}

// DNSResource contains the answer, authority, and additional sections of the
// DNS message.
//
// RFC1035:
//
// The answer, authority, and additional sections all share the same format: a
// variable number of resource records, where the number of records is specified
// in the corresponding count field in the header. Each resource record has the
// following format:
//
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type DNSResource struct {
	Name     string   // Domain name
	Type     DNSType  // RData type
	Class    DNSClass // RData class
	TTL      uint32   // Time to live
	RDLength uint16   // RData length

	// The following values encode the RData values. Depending on the
	// DNSType, one or more of the values are filled in.

	RData []byte // Raw resource data, for any unknown DNSType

	Address net.IP // 32bit Internet address, for DNSTypeA

	NSDName string // Domain name, for DNSTypeNS

	CName string // Domain name, for DNSTypeCName

	MName   string // Domain name, for DNSTypeSOA
	RName   string // Domain name, for DNSTypeSOA
	Serial  uint32 // Version number, for DNSTypeSOA
	Refresh uint32 // Refresh time interval, for DNSTypeSOA
	Retry   uint32 // Retry time interval, for DNSTypeSOA
	Expire  uint32 // Expire time interval, for DNSTypeSOA
	Minimum uint32 // Minimum TTL, for DNSTypeSOA

	PTRDName string // Domain name, for DNSTypePTR

	Preference uint16 // Preference of this RR, for DNSTypeMX
	Exchange   string // Domain name, for DNSTypeMX

	TXT []string // Text, for DNSTypeTXT
}

func (r *DNSResource) decode(data []byte, offset int) (int, error) {
	// Decode the variable length domain name, that starts at the offset we
	// are given. It returns the decoded domain name and the offset from
	// which we should continue decoding this resource if there is no error;
	// otherwise it returns an error and we cannot continue decoding this
	// DNS message.
	name, offset, err := decodeDomainName(data, offset)
	if err != nil {
		return 0, err
	}

	r.Name = name
	// Type is 16 bits, so decode the first two bytes from the offset.
	r.Type = DNSType(binary.BigEndian.Uint16(data[offset : offset+2]))
	// Class is 16 bits, so decode the second two bytes from the offset.
	r.Class = DNSClass(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	// TTL is 32 bits, so decode the four bytes following the Class.
	r.TTL = binary.BigEndian.Uint32(data[offset+4 : offset+8])
	// RDLength is 16 bits, so we decode the two bytes following the TTL.
	r.RDLength = binary.BigEndian.Uint16(data[offset+8 : offset+10])

	offset += 10
	// A malicious DNS message may contain a length that is longer than the
	// DNS message, so check for this.
	if offset+int(r.RDLength) > len(data) {
		return 0, errors.New("Resource length is longer than the message length")
	}

	switch r.Type {
	case DNSTypeA:
		// Golang's net.IP is merely a "typedef" of a byte slice, we can
		// simply refer to the right section in the data. The advantage
		// of using net.IP is that it has a nice print method defined on
		// it, nothing more.
		r.Address = data[offset : offset+int(r.RDLength)]
	case DNSTypeNS:
		// Decode a variable length domain name as before, where the new
		// offset does not matter anymore because we already have
		// RDLength.
		r.NSDName, _, err = decodeDomainName(data, offset)
		if err != nil {
			return 0, err
		}
	case DNSTypeCName:
		r.CName, _, err = decodeDomainName(data, offset)
		if err != nil {
			return 0, err
		}
	case DNSTypeSOA:
		var tmp_offset int
		// Decode a variable length domain name, where the offset does
		// matter in order to decode the remainder of this data. We
		// don't use `offset` here because that is used in the return
		// statement at the end of this function.
		r.MName, tmp_offset, err = decodeDomainName(data, offset)
		if err != nil {
			return 0, err
		}
		r.RName, tmp_offset, err = decodeDomainName(data, tmp_offset)
		if err != nil {
			return 0, err
		}
		r.Serial = binary.BigEndian.Uint32(data[tmp_offset : tmp_offset+4])
		r.Refresh = binary.BigEndian.Uint32(data[tmp_offset+4 : tmp_offset+8])
		r.Retry = binary.BigEndian.Uint32(data[tmp_offset+8 : tmp_offset+12])
		r.Expire = binary.BigEndian.Uint32(data[tmp_offset+12 : tmp_offset+16])
		r.Minimum = binary.BigEndian.Uint32(data[tmp_offset+16 : tmp_offset+20])
	case DNSTypePTR:
		// Decode a variable length domain name as before, where the new
		// offset does not matter anymore because we already have
		// RDLength.
		r.PTRDName, _, err = decodeDomainName(data, offset)
		if err != nil {
			return 0, err
		}
	case DNSTypeMX:
		r.Preference = binary.BigEndian.Uint16(data[offset : offset+2])
		r.Exchange, _, err = decodeDomainName(data, offset+2)
		if err != nil {
			return 0, err
		}
	case DNSTypeTXT:
		r.TXT, err = decodeCharacterStrings(data[offset : offset+int(r.RDLength)])
		if err != nil {
			return 0, err
		}
	default:
		// For any unknown RData type, we simply refer to the right
		// section in the raw data.
		r.RData = data[offset : offset+int(r.RDLength)]
	}

	return offset + int(r.RDLength), nil
}

// String returns a string representation of the DNSResource struct.
func (r DNSResource) String() string {
	var rdata string
	switch r.Type {
	case DNSTypeA:
		rdata = fmt.Sprintf("%v ]", r.Address)
	case DNSTypeNS:
		rdata = fmt.Sprintf("%v ]", r.NSDName)
	case DNSTypeCName:
		rdata = fmt.Sprintf("%v ]", r.CName)
	case DNSTypeSOA:
		rdata = fmt.Sprintf("[ MName: %v, RName: %v, Serial: %v, Refresh: %v, Retry: %v, Expire: %v, Minimum: %v ] ]",
			r.MName, r.RName, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum)
	case DNSTypePTR:
		rdata = fmt.Sprintf("%v ]", r.PTRDName)
	case DNSTypeMX:
		rdata = fmt.Sprintf("[ Preference: %v, Exchange: %v ] ]", r.Preference, r.Exchange)
	case DNSTypeTXT:
		rdata = "TXT: ["
		if len(r.TXT) > 0 {
			for _, txt := range r.TXT {
				rdata += fmt.Sprintf("\n\t\t\t\t%v", txt)
			}
			rdata += "\n\t\t\t]\n\t\t]"
		} else {
			rdata += "TXT: []\n\t\t]"
		}
	default:
		rdata = fmt.Sprintf("%v ]", r.RData)
	}

	return fmt.Sprintf("Resource: [ Name: %v, Type: %v, Class: %v, TTL: %v, RDLength: %v, RData: %v",
		r.Name, r.Type, r.Class, r.TTL, r.RDLength, rdata)
}

// DNS contains the data of a single DNS message.
//
// RFC1035:
//
// All communications inside of the domain protocol are carried in a single
// format called a message. The top level format of message is divided into 5
// sections (some of which are empty in certain cases) shown below:
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
// The header section is always present.  The header includes fields that
// specify which of the remaining sections are present, and also specify
// whether the message is a query or a response, a standard query or some
// other opcode, etc.
//
// The names of the sections after the header are derived from their use in
// standard queries.  The question section contains fields that describe a
// question to a name server.  These fields are a query type (QTYPE), a
// query class (QCLASS), and a query domain name (QNAME).  The last three
// sections have the same format: a possibly empty list of concatenated
// resource records (RRs).  The answer section contains RRs that answer the
// question; the authority section contains RRs that point toward an
// authoritative name server; the additional records section contains RRs
// which relate to the query, but are not strictly answers for the
// question.
type DNS struct {
	Header      DNSHeader     // Header of this message
	Questions   []DNSQuestion // Questions for the name server
	Answers     []DNSResource // RRs answering the question
	Authorities []DNSResource // RRs pointing towards an authority
	Additionals []DNSResource // RRs holding additional information
}

// DecodeDNS takes a byte slice and attempts to decode the bytes into a DNS
// struct.
func DecodeDNS(data []byte) (*DNS, error) {
	dns := &DNS{}
	err := dns.decode(data)
	if err != nil {
		return &DNS{}, err
	}
	return dns, nil
}

// decode takes a byte slice and attempts to decode the bytes into the DNS
// struct it was called on.
func (d *DNS) decode(data []byte) error {
	// DNS messages have a header of 12 bytes that is always present. If
	// the passed byte slice is smaller than that, it is invalid.
	if len(data) < 12 {
		return errors.New("Too small byte slice supplied")
	}

	// Decode the header.
	d.Header = DNSHeader{}
	offset, err := d.Header.decode(data, 0)

	// Iterate over all the questions and decode them into DNSQuestion
	// structs.
	for i := 0; i < int(d.Header.QDCount); i++ {
		var q DNSQuestion
		offset, err = q.decode(data, offset)
		if err != nil {
			return err
		}
		d.Questions = append(d.Questions, q)
	}

	// Iterate over all the answers and decode them into DNSResource
	// structs.
	for i := 0; i < int(d.Header.ANCount); i++ {
		var r DNSResource
		offset, err = r.decode(data, offset)
		if err != nil {
			return err
		}
		d.Answers = append(d.Answers, r)
	}

	// Iterate over all the authorities and decode them into DNSResource
	// structs.
	for i := 0; i < int(d.Header.NSCount); i++ {
		var r DNSResource
		offset, err = r.decode(data, offset)
		if err != nil {
			return err
		}
		d.Authorities = append(d.Authorities, r)
	}

	// Iterate over all the additionals and decode them into DNSResource
	// structs.
	for i := 0; i < int(d.Header.ARCount); i++ {
		var r DNSResource
		offset, err = r.decode(data, offset)
		if err != nil {
			return err
		}
		d.Additionals = append(d.Additionals, r)
	}

	return nil
}

// String returns a string representation of the DNS struct.
func (d DNS) String() string {
	var questions string
	if d.Header.QDCount > 0 {
		questions = "Questions: ["
		for _, q := range d.Questions {
			questions += fmt.Sprintf("\n\t\t%+v", q)
		}
		questions += "\n\t]"
	} else {
		questions = "Questions: []"
	}

	answers := printResources("Answers: [", "Answers: []", d.Header.ANCount, d.Answers)
	authorities := printResources("Authorities: [", "Authorities: []", d.Header.NSCount, d.Authorities)
	additionals := printResources("Additionals: [", "Additionals: []", d.Header.ARCount, d.Additionals)

	return fmt.Sprintf("DNS: [\n\t%+v\n\t%v\n\t%v\n\t%v\n\t%v\n]", d.Header,
		questions, answers, authorities, additionals)
}

func printResources(init, empty string, count uint16, resources []DNSResource) string {
	if count > 0 {
		res := init
		for _, r := range resources {
			res += fmt.Sprintf("\n\t\t%v", r)
		}
		res += "\n\t]"
		return res
	}
	return empty
}

// From RFC1035, section 3.1:
//
// Domain names in messages are expressed in terms of a sequence of labels.
// Each label is represented as a one octet length field followed by that
// number of octets.  Since every domain name ends with the null label of
// the root, a domain name is terminated by a length byte of zero.  The
// high order two bits of every length octet must be zero, and the
// remaining six bits of the length field limit the label to 63 octets or
// less.
//
// To simplify implementations, the total length of a domain name (i.e.,
// label octets and label length octets) is restricted to 255 octets or
// less.
func decodeDomainName(data []byte, offset int) (string, int, error) {
	// A malicious DNS message can contain a pointer to a prior name
	// occurance that is too large, so we check for that explicitly at the
	// beginning of this function.
	if offset >= len(data) {
		return "", 0, errors.New("Offset too large")
	}

	index := offset
	var buffer bytes.Buffer
	// While we do not reach the zero length octet, we decode the name.
	for data[index] != 0x00 {
		// Message compression, see RFC1035 section 4.1.4.
		if data[index]&0xc0 == 0xc0 {
			// A malicious DNS message can contain a single length
			// octet with the value 0xc0, which will be interpreted
			// as a pointer with the length of two octets.
			if index+2 > len(data) {
				return "", 0, errors.New("Name pointer incomplete")
			}
			// The offset is the remaining 6 bits of the two-octet
			// pointer. To decode it, we take the whole 16 bits and
			// AND them with ~0xc0 = 0x3fff.
			nOffset := int(binary.BigEndian.Uint16(data[index:index+2])) & 0x3fff
			// Use recursion to decode the domain name at nOffset,
			// where the check for an invalid offset is made in the
			// recursive call.
			name, _, err := decodeDomainName(data, nOffset)
			if err != nil {
				return "", 0, err
			}
			return name, index + 2, nil
		} else {
			// Get the number of octets of this label.
			length := index + int(data[index]) + 1
			// A label may be 63 octets or less, see RFC 1035 section 2.3.4.
			if length-index > 63 || length > len(data) {
				return "", 0, errors.New("Label length too long")
			}

			// Write the label into the buffer and append a period
			buffer.Write(data[index+1 : length])
			buffer.WriteString(".")
			index = length
		}
	}

	name := buffer.String()
	// Remove the last appended period, if any.
	if last := len(name) - 1; last >= 0 && name[last] == '.' {
		name = name[:last]
	}
	return name, index + 1, nil
}

// RFC1035:
//
// <character-string> is a single length octet followed by that number of
// characters.  <character-string> is treated as binary information, and can be
// up to 256 characters in length (including the length octet).
func decodeCharacterStrings(data []byte) ([]string, error) {
	var strings []string

	// Start decoding the character string at the first byte, which should
	// be a length octect. We read in the length octet and check if it is
	// valid, after which we append the bytes ranging from index+1 to length
	// to the slice of strings. Finally, we set the new index to the old
	// length and repeat this, until we reach the point where the index is
	// out of bounds.
	for index, length := 0, 0; index < len(data); index = length {
		length = index + int(data[index]) + 1
		if length > len(data) {
			return []string{}, errors.New("Character string length too long")
		}
		strings = append(strings, string(data[index+1:length]))
	}
	return strings, nil
}
