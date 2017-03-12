package module

import (
	"github.com/Hjdskes/ET4397IN/config"
	"github.com/Hjdskes/ET4397IN/hub"
)

// A module is a piece of code performing one task of the Intrusion Prevention
// System.  It receives its packets over the message bus (see Hub) and is in
// part a Subscriber.
//
// Any module wishing to receive packets from the network interface card or a
// dumped file, should subscribe to the topic "packet". A message under this
// topic is a single gopacket.Packet.
type Module interface {
	hub.Subscriber

	// Init can be implemented to initialize the module. See
	// config.Configuration.
	Init(config *config.Configuration) error
}
