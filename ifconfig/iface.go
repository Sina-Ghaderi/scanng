package ifconfig

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

// NetLinkData contain network interface names + ip address
type NetLinkData struct {
	Name   string      // interface name
	IPNets []net.IPNet // ip v4 addresses
}

// Adapters Get List of network interfaces with ipv4 address
func Adapters() ([]NetLinkData, error) {
	var awins []NetLinkData
	ai, err := getAdapterList()
	if err != nil {
		return nil, err
	}
	for ; ai != nil; ai = ai.Next {
		name := bytePtrToString(&ai.AdapterName[0])
		awin := NetLinkData{Name: name}
		iai := &ai.IpAddressList
		for ; iai != nil; iai = iai.Next {
			ip := net.ParseIP(bytePtrToString(&iai.IpAddress.String[0]))
			mask := parseIPv4Mask(bytePtrToString(&iai.IpMask.String[0]))
			awin.IPNets = append(awin.IPNets, net.IPNet{IP: ip, Mask: mask})
		}
		awins = append(awins, awin)
	}
	return awins, nil
}

func parseIPv4Mask(ipStr string) net.IPMask {
	ip := net.ParseIP(ipStr).To4()
	return net.IPv4Mask(ip[0], ip[1], ip[2], ip[3])
}

func bytePtrToString(p *uint8) string {
	a := (*[10000]uint8)(unsafe.Pointer(p))
	i := 0
	for a[i] != 0 {
		i++
	}
	return string(a[:i])
}

func getAdapterList() (*syscall.IpAdapterInfo, error) {
	b := make([]byte, 1000)
	l := uint32(len(b))
	a := (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	err := syscall.GetAdaptersInfo(a, &l)
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		b = make([]byte, l)
		a = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
		err = syscall.GetAdaptersInfo(a, &l)
	}
	if err != nil {
		return nil, os.NewSyscallError("GetAdaptersInfo", err)
	}
	return a, nil
}

// Getsysrange gets all system ipv4 ranges
func Getsysrange(apipa bool) (nets []string) {
	ips, err := Adapters()
	if err != nil {
		return []string{"192.168.1.0/24"}
	}

	for _, i := range ips {
		for _, j := range i.IPNets {
			if !apipa && j.Contains(net.ParseIP("169.254.67.143")) {
				continue
			}
			_, ipnetA, _ := net.ParseCIDR(j.String())
			nets = append(nets, ipnetA.String())
		}
	}
	return RemoveDuplicates(nets)
}

// RemoveDuplicates remove duplicates in slice of string
func RemoveDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == true {
		} else {
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}
