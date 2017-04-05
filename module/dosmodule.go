package module

import (
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/Hjdskes/ET4397IN/config"
	"github.com/Hjdskes/ET4397IN/hub"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DoSModule struct {
	Hub   *hub.Hub
	Mutex *sync.Mutex

	cons      map[string]bool // Table tracking all the connected states.
	threshold int32           // Threshold (in packets) which when crossed within the interval signals an attack.
	syns      int32           // Amount of SYNs received within the current interval.
	ticker    *time.Ticker    // The ticker that asynchonously, periodically resets the amount of SYNs.
	fwdIP     net.IP          // IP to forward packets to.
	ownIP     net.IP          // IP of the host on which the IPS runs.
}

func (m *DoSModule) Init(config *config.Configuration) error {
	m.cons = make(map[string]bool)
	m.threshold = config.SynThreshold

	// Parse and set the forwarding IP address.
	m.fwdIP = net.ParseIP(config.ForwardIP)
	if m.fwdIP == nil {
		log.Fatal("Can't parse forwarding IP address: %s\n", config.ForwardIP)
	}
	m.fwdIP = m.fwdIP.To4()
	if m.fwdIP == nil {
		log.Fatal("Can't convert forwarding IP address to IPv4: %s\n", config.ForwardIP)
	}

	// Find the first local IP address.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				m.ownIP = ipnet.IP.To4()
				log.Println("Found local IP:", m.ownIP)
				break
			}
		}
	}

	// Start a ticker that periodically, asynchronously resets the current
	// SYN count.
	m.ticker = time.NewTicker(time.Duration(config.SynInterval) * time.Millisecond)
	go func() {
		for {
			select {
			case <-m.ticker.C:
				m.Mutex.Lock()
				m.syns = 0
				m.Mutex.Unlock()
			}
		}
	}()

	// Seed rand which is used to determine if a SYN packet should be forwarded.
	rand.Seed(time.Now().Unix())

	return nil
}

func (m *DoSModule) Topics() []string {
	return []string{"packet"}
}

func (m *DoSModule) Receive(args []interface{}) bool {
	packet, ok := args[0].(gopacket.Packet)
	if !ok {
		log.Println("DoSModule received data that was not a packet")
		return true
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return true
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return true
	}

	ip := &layers.IPv4{}
	ipData := ipLayer.LayerContents()
	ip.DecodeFromBytes(ipData, gopacket.NilDecodeFeedback)

	tcp := &layers.TCP{}
	data := tcpLayer.LayerContents()
	tcp.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	if tcp.SYN && !tcp.ACK {
		m.Mutex.Lock()
		m.syns = m.syns + 1
		m.Mutex.Unlock()
		// If the handshake has not been completed, and the threshold is
		// crossed within the current interval, we rate limit this
		// packet by forwarding it with a change 1/100.
		if !m.cons[string(ip.SrcIP)] && m.syns > m.threshold {
			if rand.Intn(100) == 1 {
				return true
			}
			m.sendReset(ip, tcp)
			return false
		}
	} else if tcp.ACK && !tcp.SYN {
		m.Mutex.Lock()
		m.cons[string(ip.SrcIP)] = true
		m.Mutex.Unlock()
	}

	return true
}

func (m *DoSModule) sendReset(ip *layers.IPv4, tcp *layers.TCP) {
	tmp := ip.DstIP
	ip.DstIP = ip.SrcIP
	ip.SrcIP = tmp

	m.send(ip, &layers.TCP{
		SrcPort: tcp.SrcPort,
		DstPort: tcp.DstPort,
		Seq:     tcp.Seq + 1,
		Ack:     tcp.Ack,
		RST:     true,
		Window:  tcp.Window,
	})
}

func (m *DoSModule) send(ip *layers.IPv4, tcp *layers.TCP) {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ipHeaderBuf, options)
	if err != nil {
		log.Println(err)
		return
	}
	ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if err != nil {
		log.Println(err)
		return
	}
	tcp.SetNetworkLayerForChecksum(ip)
	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tcpPayloadBuf, options, tcp)
	if err != nil {
		log.Println(err)
		return
	}

	var packetConn net.PacketConn
	var rawConn *ipv4.RawConn
	packetConn, err = net.ListenPacket("ip4:tcp", m.ownIP.String())
	if err != nil {
		log.Println(err)
		return
	}
	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		log.Println(err)
		return
	}

	err = rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil)
	if err != nil {
		log.Println(err)
	}
}
