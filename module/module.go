package module

import "github.com/google/gopacket"

type Module interface {
	LayerType() gopacket.LayerType
	Process(data []byte)
}
