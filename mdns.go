// Package mdns ...
// Advertise network services via multicast DNS
package mdns

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Zone holds all published entries.
type Zone struct {
	records   map[dns.RR]struct{}
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
		records:   make(map[dns.RR]struct{}),
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

type query struct {
	question dns.Question
	in       chan dns.RR
}

func (z *Zone) joinMulticast() error {
	z.ifaces = listMulticastInterfaces()
	if z.ifaces == nil || len(z.ifaces) == 0 {
		return fmt.Errorf("no interfaces found")
	}
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
		if err := zone.listen(ipv4Addr); err != nil {
			return fmt.Errorf("ipv4 listen failed: %s", err)
		}
		zone.wg.Add(2)
	}

	if ipv6 {
		if err := zone.listen(ipv6Addr); err != nil {
			return fmt.Errorf("ipv6 listen failed: %s", err)
		}
		zone.wg.Add(2)
	}
	return nil
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
	z.nullAndClose()
	z.wg.Wait()
}

func (z *Zone) mainloop() {
	defer z.wg.Done()
	for {
		select {
		case in := <-z.add:
			z.records[in] = struct{}{}
		case in := <-z.remove:
			for rr := range z.records {
				if !dns.IsDuplicate(in, rr) {
					continue
				}
				delete(z.records, rr)
				resp := new(dns.Msg)
				resp.MsgHdr.Response = true
				resp.Answer = []dns.RR{null(rr)}
				err := z.multicastResponse(resp)
				if err != nil {
					log.Printf("REMOVE: %s: %v", in.String(), err)
				}
			}
		case query := <-z.lookup:
			for rr := range z.records {
				if query.question.Name == fqdn(rr) && matches(query.question, rr) {
					query.in <- rr
				}
			}
			close(query.in)
		case in := <-z.broadcast:
			var out []dns.RR
			for rr := range z.records {
				out = append(out, rr)
			}
			in <- out
			close(in)
		case in := <-z.destroy:
			var out []dns.RR
			for rr := range z.records {
				out = append(out, rr)
			}
			in <- out
			close(in)
			close(z.shutdown)
			return
		}
	}
}

func fqdn(rr dns.RR) string {
	return rr.Header().Name
}

func matches(question dns.Question, entry dns.RR) bool {
	return question.Qtype == dns.TypeANY || question.Qtype == entry.Header().Rrtype
}

func (z *Zone) bcastEntries() {
	defer z.wg.Done()
	var jitter time.Duration = time.Millisecond * 100 * time.Duration(rand.Intn(10))
	for {
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
			z.tryJoinMulticast()
		}
		select {
		case <-z.shutdown:
			return
		case <-time.NewTimer(time.Second*5 + jitter).C:
		}
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

func (z *Zone) tryJoinMulticast() {
	var retry time.Duration = time.Second
	for {
		err := z.joinMulticast()
		if err == nil {
			return
		}
		select {
		case <-z.shutdown:
			return
		case <-time.NewTimer(retry).C:
			if retry < time.Second*20 {
				retry *= 2
			}
		}

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

func (z *Zone) nullAndClose() {
	entries := make(chan []dns.RR)
	z.destroy <- entries
	var nulled []dns.RR
	for _, v := range <-entries {
		nulled = append(nulled, null(v))
	}
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true
	resp.Answer = nulled
	z.multicastResponse(resp)
	if z.net4 != nil {
		z.net4.Close()
	}
	if z.net6 != nil {
		z.net6.Close()
	}
}

type connector struct {
	*net.UDPConn
	*Zone
}

func openSocket(addr *net.UDPAddr) (*net.UDPConn, error) {
	switch addr.IP.To4() {
	case nil:
		return net.ListenMulticastUDP("udp6", nil, ipv6Addr)
	default:
		return net.ListenMulticastUDP("udp4", nil, ipv4Addr)
	}
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

type packet struct {
	*dns.Msg
	*net.UDPAddr
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

// recursively probe for related records
func (c *connector) findExtra(r ...dns.RR) (extra []dns.RR) {
	for _, rr := range r {
		var q dns.Question
		switch rr := rr.(type) {
		case *dns.PTR:
			q = dns.Question{
				Name:   rr.Ptr,
				Qtype:  dns.TypeANY,
				Qclass: dns.ClassINET,
			}
		case *dns.SRV:
			q = dns.Question{
				Name:   rr.Target,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
		default:
			continue
		}
		res := lookup(c.lookup, q)
		if len(res) > 0 {
			for _, rr := range res {
				extra = append(append(extra, rr), c.findExtra(rr)...)
			}
		}
	}
	return extra
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
		msg.Answer = dns.Dedup(msg.Answer, make(map[string]dns.RR))
		msg.Extra = append(msg.Extra, c.findExtra(msg.Answer...)...)
		msg.Extra = dns.Dedup(msg.Extra, make(map[string]dns.RR))
		if len(msg.Answer) > 0 {
			// nuke questions
			msg.Question = nil
			if err := c.writeMessage(msg.Msg, msg.UDPAddr); err != nil {
				log.Printf("cannot send: %s", err)
			}
		}
	}
}
