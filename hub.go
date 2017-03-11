// This package implements simple publish / subscribe processing, inspired after
// https://github.com/vtg/pubsub.
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

// TODO: make *[]byte? Currently, the byte slice might is copied for every
// call, which lowers performance. However, modules that (accidentally) modify
// the data now do not interfere with eachother.
type message struct {
	topic string
	args  []interface{}
}

type subscriber struct {
	topics  []string
	handler func([]interface{})
}

// The Hub struct is the "broker" through which all messages go.
type Hub struct {
	pub         chan message
	sub         chan subscriber
	subscribers map[string][]subscriber
}

// Create a new Hub.
func NewHub() *Hub {
	return &Hub{
		pub:         make(chan message),
		sub:         make(chan subscriber),
		subscribers: make(map[string][]subscriber),
	}
}

// Publish the data to be passed to any subscriber subscribed to this topic.
func (h *Hub) Publish(topic string, args ...interface{}) {
	h.pub <- message{topic, args}
}

// Subscribe to be passed any data meant for these topics.
func (h *Hub) Subscribe(topics []string, handler func([]interface{})) {
	h.sub <- subscriber{topics, handler}
}

// Start the hub; run this before you start adding subscribers and publishing
// messages.
func (h *Hub) Start() {
	// A goroutine to handle new subscribers. The Subscribe method above
	// sends new subscribers on the sub channel, which are received here and
	// added to the list of subscribers for those particular topics.
	go func() {
		for {
			sub := <-h.sub
			for _, topic := range sub.topics {
				h.subscribers[topic] = append(h.subscribers[topic], sub)
			}
		}
	}()

	// A goroutine to handle new messages. The Publish method above sends
	// new messages on the pub channel, which are received here. For each
	// registered topic, it is checked if it matches the topic of the
	// received message. If so, the message's arguments are sent to each
	// subscriber subscribed to that topic.
	go func() {
		for {
			msg := <-h.pub
			for topic, subs := range h.subscribers {
				if topic == msg.topic {
					for _, sub := range subs {
						sub.handler(msg.args)
					}
				}
			}
		}
	}()
}
