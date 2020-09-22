package scream

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// PingHost Send a icmp packet and wait for reply, and return icmp reply time
func PingHost(addr string, blackout int) (*net.IPAddr, time.Duration, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	dst, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		return nil, 0, err
	}

	// Make a new hello message
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte(""),
		},
	}
	b, err := m.Marshal(nil)
	if err != nil {
		return dst, 0, err
	}

	// send hi to destination
	start := time.Now()
	n, err := c.WriteTo(b, dst)
	if err != nil {
		return dst, 0, err
	} else if n != len(b) {
		return dst, 0, fmt.Errorf("can not write all data, wrote: %v, data: %v", n, len(b))
	}

	// catch the reply
	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(time.Duration(blackout) * time.Second))
	if err != nil {
		return dst, 0, err
	}
	n, peer, err := c.ReadFrom(reply)
	if err != nil {
		return dst, 0, err
	}
	duration := time.Since(start)
	rm, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return dst, 0, err
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return dst, duration, nil
	default:
		return dst, 0, fmt.Errorf("mismatch data, %v and %v", rm, peer)
	}
}
