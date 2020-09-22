package scream

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// StartPscan start port scanning tcp or udp (or both)
func StartPscan(host string, timeout time.Duration, gt int64, portstruct ...PortType) []PoutComming {
	infop := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00}
	resportscan := []PoutComming{}
	scanreslock := sync.Mutex{}
	dummg := sync.WaitGroup{}
	semap := NewWeighted(gt)
	pscantcpfunc := func(ip string, port int, pscansig string, timeout time.Duration) {
		conn, err := net.DialTimeout(pscansig, fmt.Sprintf("%s:%d", ip, port), timeout)
		if err != nil {
			scanreslock.Lock()
			resportscan = append(resportscan, PoutComming{Stat: "close", Number: port, Ptype: pscansig})
			scanreslock.Unlock()
			return
		}
		defer conn.Close()
		scanreslock.Lock()
		resportscan = append(resportscan, PoutComming{Stat: "open", Number: port, Ptype: pscansig})
		scanreslock.Unlock()
	}

	pscanudpfunc := func(ip string, port int, pscansig string, timeout time.Duration) {
		conn, err := net.DialTimeout(pscansig, fmt.Sprintf("%s:%d", ip, port), timeout)
		if err != nil {
			scanreslock.Lock()
			resportscan = append(resportscan, PoutComming{Stat: "close", Number: port, Ptype: pscansig})
			scanreslock.Unlock()
			return
		}
		defer conn.Close()
		// so for scanning udp ports we have to say something to server and wait for response,
		// its pretty sucks

		// here we write infop payload on udp connection
		_, err = conn.Write(infop)
		if err != nil {
			// in case something goes wrong ...
			scanreslock.Lock()
			resportscan = append(resportscan, PoutComming{Stat: "close", Number: port, Ptype: pscansig})
			scanreslock.Unlock()
			return
		}
		// buffer
		buffer := make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buffer)
		if err != nil {
			scanreslock.Lock()
			resportscan = append(resportscan, PoutComming{Stat: "close", Number: port, Ptype: pscansig})
			scanreslock.Unlock()
			return
		}
		// check for any response
		if buffer == nil || n == 0 {
			scanreslock.Lock()
			resportscan = append(resportscan, PoutComming{Stat: "close", Number: port, Ptype: pscansig})
			scanreslock.Unlock()
			return
		}
		scanreslock.Lock()
		resportscan = append(resportscan, PoutComming{Stat: "open", Number: port, Ptype: pscansig})
		scanreslock.Unlock()

	}

	for _, port := range portstruct {
		semap.Acquire(context.TODO(), 1)
		dummg.Add(1)
		go func(port PortType) {
			defer semap.Release(1)
			defer dummg.Done()
			if port.Tp == "TCP" {
				pscantcpfunc(host, port.Nm, "tcp", timeout)
				return
			}
			if port.Tp == "UDP" {
				pscanudpfunc(host, port.Nm, "udp", timeout)
				return
			}
			pscantcpfunc(host, port.Nm, "tcp", timeout)
			pscanudpfunc(host, port.Nm, "udp", timeout)
		}(port)
	}
	dummg.Wait()
	return resportscan
}

// DetectWeb return webserver name and an error
func DetectWeb(addr string, port int) (string, error) {
	sndreq := http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := sndreq.Get(fmt.Sprintf("http://%v:%v", addr, port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return resp.Header.Values("Server")[0], nil

}

// ScanResults implement CustomScanTCP and CustomScanUDP
type ScanResults interface {
	PortInfo() string
	SigPort() string
	StatInfo() (bool, int)
}

// CustomScanTCP struct type for tcp scan
type CustomScanTCP struct {
	OK bool
	NM int
}

// CustomScanUDP struct type for udp scan
type CustomScanUDP struct {
	OK bool
	NM int
}

// CustomPscan start port scanning tcp or udp (or both) for port mapper tool
func CustomPscan(host string, timeout time.Duration, gt int64, rgscan []int, udpmsg []byte, contype bool, ch chan<- ScanResults) {
	dummg := sync.WaitGroup{}
	semap := NewWeighted(gt)
	defer func() {
		dummg.Wait()
		close(ch)
	}()
	pscantcpfunc := func(ip string, port int, pscansig string, timeout time.Duration) {
		conn, err := net.DialTimeout(pscansig, fmt.Sprintf("%s:%d", ip, port), timeout)
		if err != nil {
			ch <- CustomScanTCP{OK: false, NM: port}
			return
		}
		defer conn.Close()
		ch <- CustomScanTCP{OK: true, NM: port}

	}

	pscanudpfunc := func(ip string, port int, pscansig string, timeout time.Duration) {
		conn, err := net.DialTimeout(pscansig, fmt.Sprintf("%s:%d", ip, port), timeout)
		if err != nil {
			ch <- CustomScanUDP{OK: false, NM: port}
			return
		}
		defer conn.Close()
		// so for scanning udp ports we have to say something to server and wait for response,
		// its pretty sucks

		// here we write infop payload on udp connection
		_, err = conn.Write(udpmsg)
		if err != nil {
			// in case something goes wrong ...
			ch <- CustomScanUDP{OK: false, NM: port}
			return
		}
		// buffer
		buffer := make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buffer)
		if err != nil {
			ch <- CustomScanUDP{OK: false, NM: port}
			return
		}
		// check for any response
		if buffer == nil || n == 0 {
			ch <- CustomScanUDP{OK: false, NM: port}
			return
		}
		ch <- CustomScanUDP{OK: true, NM: port}

	}

	if !contype {
		for _, port := range rgscan {
			if signal, _ := semap.AcquireSnix(context.TODO(), 1); signal != 0 {
				return
			}
			dummg.Add(1)
			go func(port int) {
				defer semap.Release(1)
				defer dummg.Done()
				pscantcpfunc(host, port, "tcp", timeout)
			}(port)
		}
	} else {
		for _, port := range rgscan {
			if signal, _ := semap.AcquireSnix(context.TODO(), 1); signal != 0 {
				return
			}
			dummg.Add(1)
			go func(port int) {
				defer semap.Release(1)
				defer dummg.Done()
				pscanudpfunc(host, port, "udp", timeout)
			}(port)
		}
	}
	dummg.Wait()

}

// SigPort return port protocol type
func (CustomScanTCP) SigPort() string {
	return "tcp"
}

// SigPort return port protocol type
func (CustomScanUDP) SigPort() string {
	return "udp"
}

// StatInfo returns stat and port number
func (p CustomScanTCP) StatInfo() (bool, int) {
	return p.OK, p.NM
}

// StatInfo returns stat and port number
func (p CustomScanUDP) StatInfo() (bool, int) {
	return p.OK, p.NM
}
