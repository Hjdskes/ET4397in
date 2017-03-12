package module

import (
	"log"

	"github.com/Hjdskes/ET4397IN/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type WriteModule struct {
	Writer *pcapgo.Writer
}

func (m WriteModule) Init(config *config.Configuration) error {
	return nil
}

func (m WriteModule) Topics() []string {
	return []string{"packet"}
}

func (m WriteModule) Receive(args []interface{}) {
	packet, ok := args[0].(gopacket.Packet)
	if !ok {
		log.Println("WriteModule received data that was not a packet")
		return
	}

	m.Writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
}
