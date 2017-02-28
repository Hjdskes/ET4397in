package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	handle *pcap.Handle
	err    error
	w      *pcapgo.Writer
)

func main() {
	// Process command-line arguments.
	device := flag.String("device", "enp9s0", "The device to capture packets from.")
	snaplen := flag.Int("snaplen", 65535, "The maximum size to read for each packet.")
	promiscuous := flag.Bool("promiscuous", false, "Put the device in promiscuous mode. (default false)")
	filePath := flag.String("path", "", "Save the recorded packets into a file specified by this flag.")
	source := flag.String("source", "", "Read packets from the file specified by this flag.")
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
				log.Error(err)
			} else {
				w = pcapgo.NewWriter(f)
				// Write the header into the file.
				w.WriteFileHeader(uint32(*snaplen), layers.LinkTypeEthernet)
				defer f.Close()
			}
		}
	}

	// Create a PacketSource, from which we can retrieve packets.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process each packet.
		fmt.Println(packet)
		if w != nil {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
}
