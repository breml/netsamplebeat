package beater

import (
	"errors"
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/elastic/beats/libbeat/beat"

	"github.com/google/gopacket/pcap"
)

func findInterfaces() ([]pcap.Interface, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, errors.New("Error getting devices list: " + err.Error())
	}
	if len(interfaces) == 0 {
		errMsg := "No devices found."
		if runtime.GOOS != "windows" {
			errMsg += " You might need sudo?"
		}
		return nil, errors.New(errMsg)
	}
	return interfaces, nil
}

func init() {
	printDevices := flag.Bool("devices", false, "Print the list of devices and exit")

	beat.AddFlagsCallback(func(_ *beat.Beat) error {
		if !*printDevices {
			return nil
		}

		interfaces, err := findInterfaces()
		if err != nil {
			fmt.Println(err.Error())
		}

		for i, iface := range interfaces {
			fmt.Printf("%d: %s ", i, iface.Name)
			if len(iface.Description) > 0 {
				fmt.Printf("(%s) ", iface.Description)
			}
			if len(iface.Addresses) > 0 {
				addrs := make([]string, len(iface.Addresses))
				for i, addr := range iface.Addresses {
					addrs[i] = addr.IP.String()
				}
				fmt.Printf("[%s]", strings.Join(addrs, ", "))
			}
			fmt.Printf("\n")
		}
		return beat.GracefulExit
	})
}
