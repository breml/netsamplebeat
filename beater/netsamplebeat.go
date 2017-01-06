package beater

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/breml/bpfutils"
	"github.com/breml/netsamplebeat/config"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Netsamplebeat holds the properties of a Netsamplebeat instance
type Netsamplebeat struct {
	done       chan struct{}
	config     config.Config
	client     publisher.Client
	interfaces []pcap.Interface
}

const (
	snapshotLen = 1024
	promiscuous = false
	timeout     = 1 * time.Second
)

var pcapFile = flag.String("I", "", "Read packet data from specified file")

// New creates a Netsamplebeat
func New(_ *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	var err error

	// Check for root privileges.
	if os.Getuid() != 0 && runtime.GOOS != "windows" {
		logp.Warn("netsamplebeat is not running with root privileges. Programm may not work properly.")
	}

	conf := config.DefaultConfig
	if err = cfg.Unpack(&conf); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	var interfaces []pcap.Interface

	if !isOffline() {
		interfaces, err = findInterfaces()
		if err != nil {
			return nil, err
		}

		valid := false
		for _, iface := range interfaces {
			if iface.Name == conf.Interface.Device {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("device '%s' is not a valid network device", conf.Interface.Device)
		}

		if len(conf.Interface.PreSamplingFilter) > 0 {
			logp.Info("validate pre sampling BPF filter '%s' on device '%s'.", conf.Interface.PreSamplingFilter, conf.Interface.Device)
			handle, err := pcap.OpenLive(conf.Interface.Device, snapshotLen, promiscuous, timeout)
			if err != nil {
				return nil, fmt.Errorf("validation of pre sampling BPF filter failed with: %v\n", err)
			}
			defer handle.Close()

			_, err = handle.CompileBPFFilter(conf.Interface.PreSamplingFilter)
			if err != nil {
				return nil, fmt.Errorf("validation of BPF pre sampling filter failed with: %v\n", err)
			}
		}

		if len(conf.Interface.PostSamplingFilter) > 0 {
			logp.Info("validate post sampling BPF filter '%s' on device '%s'.", conf.Interface.PostSamplingFilter, conf.Interface.Device)
			handle, err := pcap.OpenLive(conf.Interface.Device, snapshotLen, promiscuous, timeout)
			if err != nil {
				return nil, fmt.Errorf("validation of post sampling BPF filter failed with: %v\n", err)
			}
			defer handle.Close()

			_, err = handle.CompileBPFFilter(conf.Interface.PostSamplingFilter)
			if err != nil {
				return nil, fmt.Errorf("validation of post sampling BPF filter failed with: %v\n", err)
			}
		}
	}

	bt := &Netsamplebeat{
		done:       make(chan struct{}),
		config:     conf,
		interfaces: interfaces,
	}
	return bt, nil
}

// Run is called by libbeat to execute Netsamplebeat
func (bt *Netsamplebeat) Run(b *beat.Beat) error {
	var device string
	if isOffline() {
		device = *pcapFile
	} else {
		device = bt.resolveInterface(bt.config.Interface.Device)
	}

	logp.Info("Sampling on device '%s' with sampling rate %d.", device, bt.config.Interface.SampleRate)

	logp.Info("netsamplebeat is running! Hit CTRL-C to stop it.")
	bt.client = b.Publisher.Connect()

	var handle *pcap.Handle
	var err error

	if isOffline() {
		handle, err = pcap.OpenOffline(*pcapFile)
	} else {
		handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	}
	if err != nil {
		return err
	}
	defer handle.Close()

	bpfInstructions, err := bt.prepareBpfFilter(handle)
	if err != nil {
		return err
	}
	err = handle.SetBPFInstructionFilter(bpfInstructions)
	if err != nil {
		return err
	}

	packetChan := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for {
		select {
		case <-bt.done:
			return nil
		case packet := <-packetChan:
			if packet == nil {
				logp.Info("End of packet stream reached, exit")
				t := time.NewTimer(2 * time.Second)
				select {
				case <-bt.done:
				case <-t.C:
				}
				return nil
			}
			bt.client.PublishEvent(bt.handlePacket(b, packet))
			logp.Info("Event sent")
		}
	}
}

// Stop is called by libbeat to signal shutdown of Netsamplebeat
func (bt *Netsamplebeat) Stop() {
	err := bt.client.Close()
	if err != nil {
		logp.Warn("beat client close exited with error: %s", err.Error())
	}
	close(bt.done)
}

func (bt *Netsamplebeat) resolveInterface(nameOrID string) string {
	ifacenr, err := strconv.Atoi(nameOrID)
	if err == nil {
		if ifacenr >= 0 && ifacenr < len(bt.interfaces) {
			nameOrID = bt.interfaces[ifacenr].Name
		}
	}
	return nameOrID
}

func (bt *Netsamplebeat) prepareBpfFilter(handle *pcap.Handle) ([]pcap.BPFInstruction, error) {
	preSampleFilter, err := handle.CompileBPFFilter(bt.config.Interface.PreSamplingFilter)
	if err != nil {
		return nil, err
	}
	postSampleFilter, err := handle.CompileBPFFilter(bt.config.Interface.PostSamplingFilter)
	if err != nil {
		return nil, err
	}
	var samplerBpf []pcap.BPFInstruction
	// bpf extension rand is not implemented in libpcap, skip sampler
	// TODO: replace with "fake" sampler e.g. based on IPv4 header checksum or IPv4 identification
	if !isOffline() {
		samplerBpf = getSamplerBpf(bt.config.Interface.SampleRate, snapshotLen)
	}

	bpfInstructionsPost, err := bpfutils.ChainPcapFilter(samplerBpf, postSampleFilter, bpfutils.AND)
	if err != nil {
		return nil, err
	}
	bpfInstructions, err := bpfutils.ChainPcapFilter(preSampleFilter, bpfInstructionsPost, bpfutils.AND)
	if err != nil {
		return nil, err
	}

	return bpfInstructions, err
}

func (bt *Netsamplebeat) handlePacket(b *beat.Beat, packet gopacket.Packet) common.MapStr {
	var interfaceIndex int
	var interfaceName string
	if isOffline() {
		interfaceIndex = 0
		interfaceName = *pcapFile
	} else {
		interfaceIndex = packet.Metadata().InterfaceIndex
		interfaceName = bt.interfaces[packet.Metadata().InterfaceIndex].Name
	}
	event := common.MapStr{
		"@timestamp": common.Time(time.Now()),
		"type":       b.Name,

		"interface_index":          interfaceIndex,
		"interface_name":           interfaceName,
		"sample_rate":              bt.config.Interface.SampleRate,
		"packet_size":              packet.Metadata().Length,
		"packet_size_extrapolated": packet.Metadata().Length * bt.config.Interface.SampleRate,
	}

	if ll := packet.LinkLayer(); ll != nil {
		event.Put("link", common.MapStr{
			"type":          ll.LayerType().String(),
			"src":           ll.LinkFlow().Src().String(),
			"dst":           ll.LinkFlow().Dst().String(),
			"endpoint_type": ll.LinkFlow().EndpointType().String(),
		})
	}

	if nl := packet.NetworkLayer(); nl != nil {
		networkLayer := common.MapStr{
			"type": nl.LayerType().String(),
			"src":  nl.NetworkFlow().Src().String(),
			"dst":  nl.NetworkFlow().Dst().String(),
		}

		switch l := nl.(type) {
		case *layers.IPv4:
			networkLayer.Put("ipv4", common.MapStr{
				"protocol": l.Protocol.String(),
				"flags":    l.Flags.String(),
				"tos":      l.TOS,
				"ttl":      l.TTL,
			})
		case *layers.IPv6:
			networkLayer.Put("ipv6", common.MapStr{
				// "protocol": l.NextHeader.String(),
				"flow_label":    l.FlowLabel,
				"hop_limit":     l.HopLimit,
				"traffic_class": l.TrafficClass,
				"length":        l.Length,
			})
		}
		event.Put("network", networkLayer)
	}

	if tl := packet.TransportLayer(); tl != nil {
		transportLayer := common.MapStr{
			"type": tl.LayerType().String(),
			"src":  tl.TransportFlow().Src().String(),
			"dst":  tl.TransportFlow().Dst().String(),
		}

		switch l := tl.(type) {
		case *layers.TCP:
			tcp := common.MapStr{
				"ack": l.ACK,
				// "cwr": l.CWR,
				// "ece": l.ECE,
				"fin": l.FIN,
				// "ns": l.NS,
				"psh": l.PSH,
				"rst": l.RST,
				"syn": l.SYN,
				"urg": l.URG,
			}
			if len(l.Options) > 0 {
				options := make([]string, len(l.Options))
				for i, opt := range l.Options {
					options[i] = opt.OptionType.String()
				}
				tcp.Put("options", options)
			}
			transportLayer.Put("tcp", tcp)

		case *layers.UDP:
			transportLayer.Put("udp", common.MapStr{
				"length": l.Length,
			})
		}
		event.Put("transport", transportLayer)
	}

	return event
}

func isOffline() bool {
	return len(*pcapFile) > 0
}
