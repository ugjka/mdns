// Package mdns ...
// Advertise network services via multicast DNS
package mdns

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Zone holds all published entries.
type Zone struct {
	domains   map[string]map[dns.RR]struct{}
	add       chan dns.RR
	remove    chan dns.RR
	broadcast chan chan []dns.RR
	destroy   chan chan []dns.RR
	queries   chan *query // query exsting entries in zone
	ifaces    []net.Interface
	net4      *ipv4.PacketConn
	net6      *ipv6.PacketConn
	wg        sync.WaitGroup
	shutdown  chan struct{}
}

// New initializes a new zone.
func New(ipv4, ipv6 bool) (*Zone, error) {
	z := &Zone{
		domains:   make(map[string]map[dns.RR]struct{}),
		add:       make(chan dns.RR),
		remove:    make(chan dns.RR),
		broadcast: make(chan chan []dns.RR),
		destroy:   make(chan chan []dns.RR),
		queries:   make(chan *query, 16),
		shutdown:  make(chan struct{}),
	}
	if err := listenInit(ipv4, ipv6, z); err != nil {
		return nil, err
	}
	z.ifaces = listMulticastInterfaces()
	var err error
	if ipv4 {
		z.net4, err = joinUDP4Multicast(z.ifaces)
		if err != nil {
			return nil, err
		}
	}
	if ipv6 {
		z.net6, err = joinUDP6Multicast(z.ifaces)
		if err != nil {
			return nil, err
		}
	}
	z.wg.Add(2)
	go z.mainloop()
	go z.bcastEntries()
	return z, nil
}

func listenInit(ipv4, ipv6 bool, zone *Zone) error {
	if ipv4 == false && ipv6 == false {
		return fmt.Errorf("neither ipv4 nor ipv6 set")
	}

	if ipv4 {
		if err := zone.listen(ipv4mcastaddr); err != nil {
			return fmt.Errorf("ipv4 listen failed: %s", err)
		}
		zone.wg.Add(2)
	}

	if ipv6 {
		if err := zone.listen(ipv6mcastaddr); err != nil {
			return fmt.Errorf("ipv6 listen failed: %s", err)
		}
		zone.wg.Add(2)
	}
	return nil
}

type query struct {
	dns.Question
	result chan dns.RR
}

func fqdn(e dns.RR) string {
	return e.Header().Name
}

// Publish adds a record, described in RFC XXX
func (z *Zone) Publish(r string) error {
	rr, err := dns.NewRR(r)
	if err != nil {
		return err
	}
	z.add <- rr
	return nil
}

// Unpublish removes a record, described in RFC XXX
func (z *Zone) Unpublish(r string) error {
	rr, err := dns.NewRR(r)
	if err != nil {
		return err
	}
	z.remove <- rr
	return nil
}

// Shutdown shuts down a zone
func (z *Zone) Shutdown() {
	z.nullEntries()
	z.wg.Wait()
}

func contains(entries map[dns.RR]struct{}, entry dns.RR) bool {
	for v := range entries {
		if dns.IsDuplicate(v, entry) {
			return true
		}
	}
	return false
}

func (z *Zone) mainloop() {
	defer z.wg.Done()
	for {
		select {
		case rr := <-z.add:
			if domain, ok := z.domains[fqdn(rr)]; ok {
				if !contains(domain, rr) {
					domain[rr] = struct{}{}
				}
			} else {
				z.domains[fqdn(rr)] = make(map[dns.RR]struct{})
				z.domains[fqdn(rr)][rr] = struct{}{}
			}
		case rr := <-z.remove:
			if domain, ok := z.domains[fqdn(rr)]; ok {
				for v := range domain {
					if dns.IsDuplicate(v, rr) {
						delete(domain, v)
						resp := new(dns.Msg)
						resp.MsgHdr.Response = true
						resp.Answer = []dns.RR{null(v)}
						z.multicastResponse(resp, 0)
					}
				}
			}
		case q := <-z.queries:
			for rr := range z.domains[q.Question.Name] {
				if matches(q.Question, rr) {
					q.result <- rr
				}
			}
			close(q.result)
		case i := <-z.broadcast:
			var out []dns.RR
			for _, items := range z.domains {
				for rr := range items {
					out = append(out, rr)
				}
			}
			i <- out
			close(i)
		case i := <-z.destroy:
			var out []dns.RR
			for _, items := range z.domains {
				for rr := range items {
					out = append(out, rr)
				}
			}
			i <- out
			close(i)
			close(z.shutdown)
			return
		}
	}
}

func (z *Zone) bcastEntries() {
	defer z.wg.Done()
	for {
		time.Sleep(time.Second * 1)
		entries := make(chan []dns.RR)
		select {
		case z.broadcast <- entries:
		case <-z.shutdown:
			return
		}
		resp := new(dns.Msg)
		resp.MsgHdr.Response = true
		resp.Answer = <-entries
		z.multicastResponse(resp, 0)
		time.Sleep(time.Second * 4)
	}
}

func (z *Zone) nullEntries() {
	entries := make(chan []dns.RR)
	z.destroy <- entries
	var nullified []dns.RR
	for _, v := range <-entries {
		nullified = append(nullified, null(v))
	}
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true
	resp.Answer = nullified
	for i := 0; i < 5; i++ {
		z.multicastResponse(resp, 0)
		time.Sleep(time.Millisecond * 100)
	}
	if z.net4 != nil {
		z.net4.Close()
	}
	if z.net6 != nil {
		z.net6.Close()
	}
}

func null(rr dns.RR) dns.RR {
	switch i := rr.(type) {
	case *dns.A:
		i.Hdr.Ttl = 0
		return i
	case *dns.AAAA:
		i.Hdr.Ttl = 0
		return i
	case *dns.SRV:
		i.Hdr.Ttl = 0
		return i
	case *dns.PTR:
		i.Hdr.Ttl = 0
		return i
	case *dns.TXT:
		i.Hdr.Ttl = 0
		return i
	default:
		log.Printf("Nullifying %s not implemented", i)
		return i
	}
}

// multicastResponse us used to send a multicast response packet
func (z *Zone) multicastResponse(msg *dns.Msg, ifIndex int) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	if z.net4 != nil {
		var wcm ipv4.ControlMessage
		if ifIndex != 0 {
			wcm.IfIndex = ifIndex
			z.net4.WriteTo(buf, &wcm, ipv4Addr)
		} else {
			for _, intf := range z.ifaces {
				wcm.IfIndex = intf.Index
				z.net4.WriteTo(buf, &wcm, ipv4Addr)
			}
		}
	}

	if z.net6 != nil {
		var wcm ipv6.ControlMessage
		if ifIndex != 0 {
			wcm.IfIndex = ifIndex
			z.net6.WriteTo(buf, &wcm, ipv6Addr)
		} else {
			for _, intf := range z.ifaces {
				wcm.IfIndex = intf.Index
				z.net6.WriteTo(buf, &wcm, ipv6Addr)
			}
		}
	}
	return nil
}

func matches(question dns.Question, entry dns.RR) bool {
	return question.Qtype == dns.TypeANY || question.Qtype == entry.Header().Rrtype
}

type connector struct {
	*net.UDPConn
	*Zone
}

func (z *Zone) listen(addr *net.UDPAddr) error {
	conn, err := openSocket(addr)
	if err != nil {
		return err
	}
	c := &connector{
		UDPConn: conn,
		Zone:    z,
	}
	go c.mainloop()

	return nil
}

func openSocket(addr *net.UDPAddr) (*net.UDPConn, error) {
	switch addr.IP.To4() {
	case nil:
		return net.ListenMulticastUDP("udp6", nil, ipv6mcastaddr)
	default:
		return net.ListenMulticastUDP("udp4", nil, ipv4mcastaddr)
	}
}

type packet struct {
	*dns.Msg
	*net.UDPAddr
}

func (c *connector) readloop(in chan packet) {
	defer c.Zone.wg.Done()
	for {
		msg, addr, err := c.readMessage()
		if err != nil {
			return
		}
		if nil != msg && len(msg.Question) > 0 {
			in <- packet{msg, addr}
		}
	}
}

func queryZone(z *Zone, q dns.Question) (entries []dns.RR) {
	res := make(chan dns.RR, 16)
	z.queries <- &query{q, res}
	for e := range res {
		entries = append(entries, e)
	}
	return
}

func (c *connector) mainloop() {
	defer c.Zone.wg.Done()
	in := make(chan packet, 32)
	go c.readloop(in)
	for {
		var msg packet
		select {
		case msg = <-in:
		case <-c.Zone.shutdown:
			c.UDPConn.Close()
			return
		}
		msg.MsgHdr.Response = true // convert question to response
		var results []dns.RR
		for _, q := range msg.Question {
			results = append(results, queryZone(c.Zone, q)...)
		}
		for _, rr := range results {
			msg.Answer = append(msg.Answer, rr)
		}
		msg.Extra = []dns.RR{}
		if len(msg.Answer) > 0 {
			// nuke questions
			msg.Question = nil
			if err := c.writeMessage(msg.Msg, msg.UDPAddr); err != nil {
				log.Printf("cannot send: %s", err)
			}
		}
	}
}

// encode an mdns msg and broadcast it on the wire
func (c *connector) writeMessage(msg *dns.Msg, addr *net.UDPAddr) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	_, err = c.WriteToUDP(buf, addr)
	return err
}

// consume an mdns packet from the wire and decode it
func (c *connector) readMessage() (*dns.Msg, *net.UDPAddr, error) {
	buf := make([]byte, 1500)
	read, addr, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	var msg dns.Msg
	if err := msg.Unpack(buf[:read]); err != nil {
		return nil, nil, err
	}
	return &msg, addr, nil
}
