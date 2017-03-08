// This package implements Simple publish / subscribe processing, inspired after
// https://github.com/vtg/pubsub/blob/master/pubsub.go.
// Usage:
//
//     hub := NewHub()
//     hub.Start()
//     for ... {
//         hub.Subscribe(..., ...)
//     }
//     ...
//     hub.Publish(..., ...)
//
package main

import "github.com/google/gopacket"

// Handler function that each subscriber should implement.
type Handler func(data []byte)

// TODO: make *[]byte? Currently, the byte slice might is copied for every
// call, which lowers performance. However, modules that (accidentally) modify
// the data now do not interface with eachother.
type message struct {
	layer gopacket.LayerType
	data  []byte
}

type subscriber struct {
	layer   gopacket.LayerType
	handler Handler
}

// The Hub struct is the "broker" through which all messages go.
type Hub struct {
	pub         chan message
	sub         chan subscriber
	subscribers []subscriber
}

// Create a new Hub.
func NewHub() *Hub {
	return &Hub{
		pub:         make(chan message),
		sub:         make(chan subscriber),
		subscribers: []subscriber{},
	}
}

// Publish the data to be decoded by any subscriber handling data from this
// layer.
func (h *Hub) Publish(layer gopacket.LayerType, data []byte) {
	h.pub <- message{layer, data}
}

// Subscribe to be passed any data meant for this layer.
func (h *Hub) Subscribe(layer gopacket.LayerType, handler Handler) {
	h.sub <- subscriber{layer, handler}
}

// Start the hub; run this before you start adding subscribers and publishing
// messages.
func (h *Hub) Start() {
	// A goroutine to handle new subscribers. The Subscribe method above
	// sends new subscribers on the sub channel, which are received here and
	// appended to the list of subscribers.
	go func() {
		for {
			h.subscribers = append(h.subscribers, <-h.sub)
		}
	}()

	// A goroutine to handle new messages. The Publish method above sends
	// new messages on the pub channel, which are received here. For each
	// subscriber, it is checked if the message's layer type matches the one
	// the subscriber has subscribed for. If so, that subscriber's handler
	// function is called with the provided byte slice.
	go func() {
		for {
			c := <-h.pub
			for _, v := range h.subscribers {
				if v.layer == c.layer {
					v.handler(c.data)
				}
			}
		}
	}()
}
