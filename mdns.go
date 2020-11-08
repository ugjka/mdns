// Package mdns ...
// Advertise network services via multicast DNS
package mdns

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

var (
	ipv4mcastaddr = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}

	ipv6mcastaddr = &net.UDPAddr{
		IP:   net.ParseIP("ff02::fb"),
		Port: 5353,
	}
)

// New initializes a new zone.
func New(ipv4, ipv6 bool) (*Zone, error) {
	z := &Zone{
		records: make(map[string]map[*entry]struct{}),
		add:     make(chan *entry),
		remove:  make(chan *entry),
		queries: make(chan *query, 16),
	}
	if err := listenInit(ipv4, ipv6, z); err != nil {
		return nil, err
	}
	go z.mainloop()

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
	}

	if ipv6 {
		if err := zone.listen(ipv6mcastaddr); err != nil {
			return fmt.Errorf("ipv6 listen failed: %s", err)
		}
	}
	return nil
}

type entry struct {
	dns.RR
}

func (e *entry) fqdn() string {
	return e.Header().Name
}

type query struct {
	dns.Question
	result chan *entry
}

type entries []*entry

// Zone holds all published entries.
type Zone struct {
	records map[string]map[*entry]struct{}
	add     chan *entry // add entries to zone
	queries chan *query // query exsting entries in zone
	remove  chan *entry // remove entries from zone
}

// Publish adds a record, described in RFC XXX
func (z *Zone) Publish(r string) error {
	rr, err := dns.NewRR(r)
	if err != nil {
		return err
	}
	z.add <- &entry{rr}
	return nil
}

// Unpublish removes a record, described in RFC XXX
func (z *Zone) Unpublish(r string) error {
	rr, err := dns.NewRR(r)
	if err != nil {
		return err
	}
	z.remove <- &entry{rr}
	return nil
}

func contains(entries map[*entry]struct{}, entry *entry) bool {
	for v := range entries {
		if dns.IsDuplicate(v, entry) {
			return true
		}
	}
	return false
}

func (z *Zone) mainloop() {
	for {
		select {
		case record := <-z.add:
			if records, ok := z.records[record.fqdn()]; ok {
				if !contains(records, record) {
					records[record] = struct{}{}
				}
			} else {
				z.records[record.fqdn()] = make(map[*entry]struct{})
				z.records[record.fqdn()][record] = struct{}{}
			}
		case record := <-z.remove:
			if records, ok := z.records[record.fqdn()]; ok {
				for v := range records {
					if dns.IsDuplicate(v, record) {
						delete(records, v)
					}
				}
			}
		case q := <-z.queries:
			for record := range z.records[q.Question.Name] {
				if matches(q.Question, record) {
					q.result <- record
				}
			}
			close(q.result)
		}
	}
}

func queryZone(z *Zone, q dns.Question) (entries []*entry) {
	res := make(chan *entry, 16)
	z.queries <- &query{q, res}
	for e := range res {
		entries = append(entries, e)
	}
	return
}

func matches(question dns.Question, entry *entry) bool {
	return question.Qtype == dns.TypeANY || question.Qtype == entry.RR.Header().Rrtype
}

type connector struct {
	*net.UDPAddr
	*net.UDPConn
	*Zone
}

func (z *Zone) listen(addr *net.UDPAddr) error {
	conn, err := openSocket(addr)
	if err != nil {
		return err
	}
	c := &connector{
		UDPAddr: addr,
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

type pkt struct {
	*dns.Msg
	*net.UDPAddr
}

func (c *connector) readloop(in chan pkt) {
	for {
		msg, addr, _ := c.readMessage()
		if nil != msg && len(msg.Question) > 0 {
			in <- pkt{msg, addr}
		}
	}
}

func (c *connector) mainloop() {
	in := make(chan pkt, 32)
	go c.readloop(in)
	for {
		msg := <-in
		msg.MsgHdr.Response = true // convert question to response
		var results entries
		for _, q := range msg.Question {
			results = append(results, queryZone(c.Zone, q)...)
		}
		for _, result := range results {
			msg.Answer = append(msg.Answer, result.RR)
		}
		msg.Extra = append(msg.Extra, c.findExtra(msg.Answer...)...)
		if len(msg.Answer) > 0 {
			// nuke questions
			msg.Question = nil
			if err := c.writeMessage(msg.Msg, msg.UDPAddr); err != nil {
				log.Printf("Cannot send: %s", err)
			}
		}
	}
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
		res := queryZone(c.Zone, q)
		if len(res) > 0 {
			for _, entry := range res {
				extra = append(append(extra, entry.RR), c.findExtra(entry.RR)...)
			}
		}
	}
	return
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
