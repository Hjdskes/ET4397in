package main

import (
	"flag"
	"log"
	"os"

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
	// TODO: sensible default.
	configFile := flag.String("config", "config.json", "Path to the configuration file")
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

	// Read the configuration file.
	configuration, err = config.New(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Create the message hub.
	hub := hub.NewHub()
	hub.Start()

	// Create all the modules.
	// TODO: make the selection of modules configurable on the command-line
	modules := []module.Module{
		&module.ARPModule{Hub: hub},
		//module.DNSModule{},
		module.LogModule{},
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
	for packet := range packetSource.Packets() {
		hub.Publish("packet", packet)
	}

	// Hack to keep the program running when there are no more packets to
	// receive, this happens e.g. when all packets have been read from a
	// pcap file but not yet processed.
	for {
	}
}
