package module

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/Hjdskes/ET4397IN/config"
	"github.com/Hjdskes/ET4397IN/hub"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type WiFiModule struct {
	Hub      *hub.Hub
	interval int64 // Interval within which frames are considered to be an attack, in milliseconds.

	prevDeauthTime time.Time // Time of the previously received deauthentication or dissasociation packet was received, used to detect dissasociation or deauthentication attacks.

	prevARPPacket []byte    // Previously received ARP request, used to detect ARP replay attacks.
	prevARPTime   time.Time // Time of the previously received ARP request, used to detect ARP replay attacks.
}

func (m *WiFiModule) Init(config *config.Configuration) error {
	m.interval = config.Interval
	return nil
}

func (m *WiFiModule) Topics() []string {
	return []string{"packet"}
}

const (
	deauth = "Host %v is possibly trying to perform a disassociation or deauthentication attack"
	replay = "Host %v is possibly performing an ARP replay attack"
)

func (m *WiFiModule) Receive(args []interface{}) {
	cur := time.Now()

	packet, ok := args[0].(gopacket.Packet)
	if !ok {
		log.Println("WiFiModule received data that was not a packet")
		return
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}

	dot11 := &layers.Dot11{}
	data := dot11Layer.LayerPayload()
	dot11.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	switch dot11.Type {
	case layers.Dot11TypeMgmtDisassociation, layers.Dot11TypeMgmtDeauthentication:
		m.deauth(dot11, cur)
	case layers.Dot11TypeData:
		if dot11.Flags.WEP() {
			payload := packet.Layer(layers.LayerTypeDot11WEP).LayerPayload()
			m.arpReplay(dot11, payload, cur)
		}
	}
}

func (m *WiFiModule) deauth(dot11 *layers.Dot11, cur time.Time) {
	// If this disassociation or deauthentication frame is sent within the
	// interval, we notice this as a possible attack.
	if cur.Sub(m.prevDeauthTime)*time.Millisecond < time.Duration(m.interval) {
		m.Hub.Publish("log", "notice", fmt.Sprintf(deauth, dot11.Address1))
	}
	m.prevDeauthTime = cur
}

func (m *WiFiModule) arpReplay(dot11 *layers.Dot11, data []byte, cur time.Time) {
	// An ARP request is 28 bytes long, plus the 8 byte ICV.
	if len(data) != 28+8 {
		return
	}

	// If this WEP frame is sent within the interval and the payload matches
	// the previously received payload, we notice this as a possible attack.
	if cur.Sub(m.prevARPTime)*time.Millisecond < time.Duration(m.interval) && bytes.Equal(m.prevARPPacket, data) {
		m.Hub.Publish("log", "notice", fmt.Sprintf(replay, dot11.Address1))
	}
	m.prevARPPacket = data
	m.prevARPTime = cur
}
