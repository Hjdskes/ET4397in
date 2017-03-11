// This package implements simple publish / subscribe processing, inspired after
// https://github.com/vtg/pubsub.
package hub

// Every type wanting to subscribe on the message bus should implement the Subscriber interface.
// It dictates that the subscriber is able to declare the topics they want to receive messages for,
// and that they can receive arbitrary arguments over the message bus.
//
// The subscriber itself is responsible for converting the arguments to the correct type.
type Subscriber interface {
	// Topics returns an array of topics that the Subscriber subcribes to.
	Topics() []string

	// Receive is called when there is a message under a certain topic to which the
	// subscriber has subscribed. The message's contents are passed as arguments; the subscriber
	// is responsible for converting them to the proper format.
	Receive(args []interface{})
}

// TODO: make *[]byte? Currently, the byte slice might is copied for every
// call, which lowers performance. However, modules that (accidentally) modify
// the data now do not interfere with eachother.
type message struct {
	topic string
	args  []interface{}
}

type subscription struct {
	topics  []string
	handler func([]interface{})
}

// The Hub struct is the "broker" through which all messages go.
type Hub struct {
	pub           chan message
	sub           chan subscription
	subscriptions map[string][]subscription
}

// Create a new Hub.
func NewHub() *Hub {
	return &Hub{
		pub:           make(chan message),
		sub:           make(chan subscription),
		subscriptions: make(map[string][]subscription),
	}
}

// Publish the data to be passed to any subscriber subscribed to this topic.
func (h *Hub) Publish(topic string, args ...interface{}) {
	h.pub <- message{topic, args}
}

// Subscribe subcribes a Subscriber for all its declared topics.
func (h *Hub) Subscribe(s Subscriber) {
	h.sub <- subscription{s.Topics(), s.Receive}
}

// Start the hub. This should be run before any subscription are added or messages
// are published.
func (h *Hub) Start() {
	// A goroutine to handle new subscribers. The Subscribe method above
	// sends new subscribers on the sub channel, which are received here and
	// added to the list of subscribers for those particular topics.
	go func() {
		for {
			sub := <-h.sub
			for _, topic := range sub.topics {
				h.subscriptions[topic] = append(h.subscriptions[topic], sub)
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
			for topic, subs := range h.subscriptions {
				if topic == msg.topic {
					for _, sub := range subs {
						sub.handler(msg.args)
					}
				}
			}
		}
	}()
}
