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
	lookup    chan *query // query exsting entries in zone
	net4      *ipv4.PacketConn
	net6      *ipv6.PacketConn
	ifaces    []net.Interface
	wg        sync.WaitGroup
	shutdown  chan struct{}
	ipv4      bool
	ipv6      bool
}

// New initializes a new zone.
func New(ipv4, ipv6 bool) (*Zone, error) {
	z := &Zone{
		domains:   make(map[string]map[dns.RR]struct{}),
		add:       make(chan dns.RR),
		remove:    make(chan dns.RR),
		broadcast: make(chan chan []dns.RR),
		destroy:   make(chan chan []dns.RR),
		lookup:    make(chan *query, 16),
		shutdown:  make(chan struct{}),
		ipv4:      ipv4,
		ipv6:      ipv6,
	}
	if err := listenInit(ipv4, ipv6, z); err != nil {
		return nil, err
	}
	if err := z.joinMulticast(); err != nil {
		return nil, err
	}
	z.wg.Add(2)
	go z.mainloop()
	go z.bcastEntries()
	return z, nil
}

func (z *Zone) joinMulticast() error {
	z.ifaces = listMulticastInterfaces()
	var err error
	if z.ipv4 {
		z.net4, err = joinUDP4Multicast(z.ifaces)
		if err != nil {
			return err
		}
	}
	if z.ipv6 {
		z.net6, err = joinUDP6Multicast(z.ifaces)
		if err != nil {
			return err
		}
	}
	return nil
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
	question dns.Question
	in       chan dns.RR
}

func fqdn(rr dns.RR) string {
	return rr.Header().Name
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
	for rr := range entries {
		if dns.IsDuplicate(rr, entry) {
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
				for entry := range domain {
					if dns.IsDuplicate(entry, rr) {
						delete(domain, entry)
						resp := new(dns.Msg)
						resp.MsgHdr.Response = true
						resp.Answer = []dns.RR{null(entry)}
						var timeout time.Duration = time.Second * 1
						for {
							err := z.multicastResponse(resp)
							if err == nil {
								break
							}
							time.Sleep(timeout)
							if timeout < time.Second*20 {
								timeout *= 2
							}
							z.joinMulticast()
						}
					}
				}
			}
		case query := <-z.lookup:
			for rr := range z.domains[query.question.Name] {
				if matches(query.question, rr) {
					query.in <- rr
				}
			}
			close(query.in)
		case in := <-z.broadcast:
			var out []dns.RR
			for _, domain := range z.domains {
				for rr := range domain {
					out = append(out, rr)
				}
			}
			in <- out
			close(in)
		case in := <-z.destroy:
			var out []dns.RR
			for _, domain := range z.domains {
				for rr := range domain {
					out = append(out, rr)
				}
			}
			in <- out
			close(in)
			close(z.shutdown)
			return
		}
	}
}

func (z *Zone) bcastEntries() {
	defer z.wg.Done()
	for {
		time.Sleep(time.Second)
		entries := make(chan []dns.RR)
		select {
		case z.broadcast <- entries:
		case <-z.shutdown:
			return
		}
		resp := new(dns.Msg)
		resp.MsgHdr.Response = true
		resp.Answer = <-entries
		err := z.multicastResponse(resp)
		if err != nil {
			z.joinMulticast()
		}
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
	var timeout time.Duration = time.Second * 1
	for {
		err := z.multicastResponse(resp)
		if err == nil {
			break
		}
		time.Sleep(timeout)
		if timeout < time.Second*20 {
			timeout *= 2
		}
		z.joinMulticast()
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
		log.Printf("nulling not implemented for: %s", i)
		return i
	}
}

// multicastResponse us used to send a multicast response packet
func (z *Zone) multicastResponse(msg *dns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	if z.net4 != nil {
		var wcm ipv4.ControlMessage
		for _, intf := range z.ifaces {
			wcm.IfIndex = intf.Index
			_, err := z.net4.WriteTo(buf, &wcm, ipv4Addr)
			if err != nil {
				return err
			}
		}

	}

	if z.net6 != nil {
		var wcm ipv6.ControlMessage
		for _, intf := range z.ifaces {
			wcm.IfIndex = intf.Index
			_, err := z.net6.WriteTo(buf, &wcm, ipv6Addr)
			if err != nil {
				return err
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
	defer c.wg.Done()
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

func lookup(out chan *query, question dns.Question) (entries []dns.RR) {
	in := make(chan dns.RR, 16)
	out <- &query{question, in}
	for rr := range in {
		entries = append(entries, rr)
	}
	return entries
}

func (c *connector) mainloop() {
	defer c.wg.Done()
	in := make(chan packet, 32)
	go c.readloop(in)
	for {
		var msg packet
		select {
		case msg = <-in:
		case <-c.shutdown:
			c.Close()
			return
		}
		msg.MsgHdr.Response = true // convert question to response
		var entries []dns.RR
		for _, question := range msg.Question {
			entries = append(entries, lookup(c.lookup, question)...)
		}
		msg.Answer = append(msg.Answer, entries...)
		msg.Extra = nil
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
