package scream

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// PortType struct is a part of settings for ipscanner and port mapper
type PortType struct /*Porttype is a part of settings for ipscanner*/ {
	Nm int
	Tp string
}

var (
	// StopChan stop all procces
	StopChan = make(chan struct{}, 8)
	// PauseChan pause all goroutins
	PauseChan = make(chan struct{}, 16)
	// ContChan makes all goroutins continue
	ContChan = make(chan struct{}, 16)
)

// PoutComming struct to return scanning resualts
type PoutComming struct {
	Stat, Ptype string
	Number      int
}

//GetHosts get a cidr network range and return slice of ip addesses
func GetHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

var sysendARP = syscall.MustLoadDLL("iphlpapi.dll").MustFindProc("SendARP")

func ip4ToUint32(ip net.IP) (uint32, error) {
	if ip == nil {
		return 0, fmt.Errorf("ip address %v is not ip4", ip)
	}
	var ret uint32
	for i := 4; i > 0; i-- {
		ret <<= 8
		ret += uint32(ip[i-1])
	}
	return ret, nil
}

// SendARP used to bcast arp in network
func SendARP(ip net.IP) (net.HardwareAddr, error) {
	dst, err := ip4ToUint32(ip)
	if err != nil {
		return nil, err
	}
	mac := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	n := uint32(len(mac))
	ret, _, _ := sysendARP.Call(
		uintptr(dst),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&n)))
	if ret != 0 {
		return nil, syscall.Errno(ret)
	}
	return mac, nil
}
