package discoverservice

import (
	"fmt"
	"net"
	"testing"
)

func TestGetInterfaces(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Error(err)
	}

	for _, iface := range interfaces {
		fmt.Printf("Iface: %+v\n", iface)
		addrs, err := iface.Addrs()
		if err != nil {
			t.Error(err)
		}

		for _, addr := range addrs {
			fmt.Printf("Addr: %+v\n", addr)

			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				t.Error(err)
			}

			fmt.Printf("IP: %+v\n", ip)
			fmt.Printf("IPNet: %+v\n", ipNet)
			fmt.Printf("Mask: %+v\n", ipNet.Mask)

			bip := []byte(ip.To4())
			bmask := []byte(ipNet.Mask)

			if len(bip) != len(bmask) {
				fmt.Println(bip)
				continue
			}

			bdcst := make([]byte, len(bip))

			for i := range bip {
				bdcst[i] = bip[i] | ^bmask[i]
			}

			fmt.Printf("Broadcast: %+v\n", net.IP(bdcst))
		}
	}
}
