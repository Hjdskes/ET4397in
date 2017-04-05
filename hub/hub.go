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
	//
	// The subscriber passes its verdict in the return value, where true
	// means the package is safe and false means it's not.
	Receive(args []interface{}) bool
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
	handler func([]interface{}) bool
}

// The Hub struct is the "broker" through which all messages go.
type Hub struct {
	subscriptions map[string][]subscription
}

// Create a new Hub.
func NewHub() *Hub {
	return &Hub{
		subscriptions: make(map[string][]subscription),
	}
}

// Publish the data to be passed to any subscriber subscribed to this topic.
// Returns false as soon as one of the subscribers returns false, true
// otherwise.
func (h *Hub) Publish(topic string, args ...interface{}) bool {
	// For each registered topic, it is checked if it matches the topic of
	// the received message. If so, the message's arguments are sent to each
	// subscriber subscribed to that topic.
	subs := h.subscriptions[topic]
	for _, sub := range subs {
		if ok := sub.handler(args); !ok {
			return false
		}
	}
	return true
}

// Subscribe subcribes a Subscriber for all its declared topics.
func (h *Hub) Subscribe(s Subscriber) {
	sub := subscription{s.Topics(), s.Receive}
	for _, topic := range sub.topics {
		h.subscriptions[topic] = append(h.subscriptions[topic], sub)
	}
}
