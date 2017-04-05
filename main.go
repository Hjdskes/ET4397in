package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/Hjdskes/ET4397IN/config"
	"github.com/Hjdskes/ET4397IN/hub"
	"github.com/Hjdskes/ET4397IN/module"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	var handle *pcap.Handle
	var configuration *config.Configuration
	var w *pcapgo.Writer
	var err error

	// Process command-line arguments.
	device := flag.String("device", "enp9s0", "The device to capture packets from.")
	snaplen := flag.Int("snaplen", 65535, "The maximum size to read for each packet.")
	promiscuous := flag.Bool("promiscuous", false, "Put the device in promiscuous mode. (default false)")
	filePath := flag.String("path", "", "Save the recorded packets into a file specified by this flag. (default none)")
	source := flag.String("source", "", "Read packets from the file specified by this flag. (default none; read from device)")
	filter := flag.String("filter", "", "Set a BPF. (default none)")
	configFile := flag.String("config", "", "Path to the configuration file")
	flag.Parse()

	if *source != "" {
		// If a source file is specified, read all packets from that file.
		handle, err = pcap.OpenOffline(*source)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
	} else {
		// No source file was specified, so we open the device and read
		// the packets from there.
		handle, err = pcap.OpenLive(*device, int32(*snaplen), *promiscuous, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		// If a file path was specified, open said file to write the packets to.
		if *filePath != "" {
			f, err := os.Create(*filePath)
			if err != nil {
				log.Print(err)
			} else {
				w = pcapgo.NewWriter(f)
				// Write the header into the file.
				w.WriteFileHeader(uint32(*snaplen), layers.LinkTypeEthernet)
				defer f.Close()
			}
		}
	}

	if *filter != "" {
		// If a BPF is given, apply it.
		err = handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Read the configuration file; if it can't be found or if something
	// else goes wrong the defaults are applied.
	configuration, err = config.New(*configFile)
	if err != nil {
		log.Println(err)
	}

	// Parse and set the forwarding IP address.
	fwdIP := net.ParseIP(configuration.ForwardIP)
	if fwdIP == nil {
		log.Fatal("Can't parse forwarding IP address: %s\n", configuration.ForwardIP)
	}
	fwdIP = fwdIP.To4()
	if fwdIP == nil {
		log.Fatal("Can't convert forwarding IP address to IPv4: %s\n", configuration.ForwardIP)
	}

	// Create the message hub.
	hub := hub.NewHub()

	// Create all the modules.
	// TODO: make the selection of modules configurable on the command-line
	var mutex = &sync.Mutex{}
	modules := []module.Module{
		//&module.ARPModule{Hub: hub},
		&module.DoSModule{Hub: hub, Mutex: mutex},
		//module.DNSModule{},
		module.LogModule{},
		//&module.WiFiModule{Hub: hub},
	}

	// If there is a writer, append the WriteModule to the list of modules.
	if w != nil {
		modules = append(modules, module.WriteModule{Writer: w})
	}

	// Initialize all modules and subscribe them on the bus. If a module
	// cannot be initialized, it is not subscribed on the bus.
	for _, module := range modules {
		err = module.Init(configuration)
		if err != nil {
			log.Println(err)
		} else {
			hub.Subscribe(module)
		}
	}

	// Create a PacketSource from which we can retrieve packets.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var waitGroup sync.WaitGroup
	for packet := range packetSource.Packets() {
		waitGroup.Add(1)
		go func(waitGroup *sync.WaitGroup) {
			defer waitGroup.Done()

			if ok := hub.Publish("packet", packet); !ok {
				fmt.Println("DROP")
			} else {
				fmt.Println("FORWARD")
				forward(handle, packet, fwdIP)
			}
		}(&waitGroup)
	}

	// Wait for threads to finish.
	waitGroup.Wait()
}

func forward(handle *pcap.Handle, packet gopacket.Packet, fwdIP net.IP) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		if ip, ok := ipLayer.(*layers.IPv4); ok {
			ip.DstIP = fwdIP
		}
	}
	handle.WritePacketData(packet.Data())
}
