package module

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/Hjdskes/ET4397IN/config"
	"github.com/Hjdskes/ET4397IN/hub"
	"github.com/Hjdskes/ET4397IN/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type WiFiModule struct {
	Hub *hub.Hub

	// Interval (in nanoseconds) within which two received packets are
	// suspected to be an attack.
	interval int64

	// Time at which the last deauthentication or disassociation frame was
	// received. Used to check if the current frame is sent within the
	// interval.
	prevDeauthTime time.Time

	// Time at which the last WEP packet was received. Used to check if the
	// current WEP packet is sent within the interval.
	prevWEPTime time.Time
	// A queue of the last 10 WEP packets received. Used to compare the
	// current WEP packet with.
	weps *util.Queue
}

func (m *WiFiModule) Init(config *config.Configuration) error {
	m.interval = config.Interval
	m.weps = util.NewQueue()
	return nil
}

func (m *WiFiModule) Topics() []string {
	return []string{"packet"}
}

const (
	deauth = "Host %v is possibly performing a disassociation or deauthentication attack"
	replay = "Host %v is possibly performing an ARP replay attack"
)

func (m *WiFiModule) Receive(args []interface{}) bool {
	cur := time.Now()

	packet, ok := args[0].(gopacket.Packet)
	if !ok {
		log.Println("WiFiModule received data that was not a packet")
		return true
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return true
	}

	dot11 := &layers.Dot11{}
	data := dot11Layer.LayerPayload()
	dot11.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	switch dot11.Type {
	case layers.Dot11TypeMgmtDisassociation, layers.Dot11TypeMgmtDeauthentication:
		return m.deauth(dot11, cur)
	case layers.Dot11TypeData:
		if dot11.Flags.WEP() {
			contents := packet.Layer(layers.LayerTypeDot11WEP).LayerContents()
			return m.arpReplay(dot11, contents, cur)
		}
	}

	return true
}

func (m *WiFiModule) deauth(dot11 *layers.Dot11, cur time.Time) bool {
	// If this disassociation or deauthentication frame is sent within the
	// interval, we notice this as a possible attack.
	if cur.Sub(m.prevDeauthTime)*time.Nanosecond < time.Duration(m.interval) {
		m.Hub.Publish("log", "notice", fmt.Sprintf(deauth, dot11.Address1))
	}
	m.prevDeauthTime = cur
	return true
}

func (m *WiFiModule) arpReplay(dot11 *layers.Dot11, data []byte, cur time.Time) bool {
	// If this WEP packet is sent within the interval and the contents match
	// the contents of one of the last 10 receives packets, we notice this
	// as a possible attack.
	if cur.Sub(m.prevWEPTime)*time.Nanosecond < time.Duration(m.interval) {
		m.weps.ForEach(func(item interface{}) bool {
			wep, ok := item.([]byte)
			if !ok {
				return false
			}

			if bytes.Equal(wep, data) {
				m.Hub.Publish("log", "notice", fmt.Sprintf(replay, dot11.Address1))
				return true
			}
			return false
		})
	}

	// We only remember the last 10 WEPs.
	if m.weps.Len() == 10 {
		m.weps.Poll()
	}
	m.weps.Push(data)
	m.prevWEPTime = cur

	return true
}
