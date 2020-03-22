package mdns

// Advertise network services via multicast DNS

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
	local *Zone // the local mdns zone
)

func init() {
	var err error
	local, err = New()
	if err != nil {
		log.Fatal(err)
	}
}

// New initialized zone.
func New() (*Zone, error) {
	z := &Zone{
		entries: make(map[string]entries),
		add:     make(chan *entry),
		remove:  make(chan *entry),
		queries: make(chan *query, 16),
	}
	go z.mainloop()
	if err := z.listen(ipv4mcastaddr); err != nil {
		return nil, fmt.Errorf("Failed to listen %s: %s", ipv4mcastaddr, err)
	}

	// if we cannot listen, ignore, we really don't care about ipv6 right now
	z.listen(ipv6mcastaddr)
	return z, nil
}

// Publish adds a record, to the default zone.
func Publish(r string) error {
	return local.Publish(r)
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

func (e entries) contains(entry *entry) bool {
	for _, ee := range e {
		if equals(entry, ee) {
			return true
		}
	}
	return false
}

// Zone holds all published entries.
type Zone struct {
	entries map[string]entries
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

func (z *Zone) mainloop() {
	for {
		select {
		case entry := <-z.add:
			if !z.entries[entry.fqdn()].contains(entry) {
				z.entries[entry.fqdn()] = append(z.entries[entry.fqdn()], entry)
			}
		case entry := <-z.remove:
			if _, ok := z.entries[entry.fqdn()]; ok {
				tmp := z.entries[entry.fqdn()][:0]
				for _, e := range z.entries[entry.fqdn()] {
					if !equals(entry, e) {
						tmp = append(tmp, e)
					}
				}

				z.entries[entry.fqdn()] = tmp
				if len(z.entries[entry.fqdn()]) == 0 {
					delete(z.entries, entry.fqdn())
				}
			}
		case q := <-z.queries:
			for _, entry := range z.entries[q.Question.Name] {
				if q.matches(entry) {
					q.result <- entry
				}
			}
			close(q.result)
		}
	}
}

func (z *Zone) query(q dns.Question) (entries []*entry) {
	res := make(chan *entry, 16)
	z.queries <- &query{q, res}
	for e := range res {
		entries = append(entries, e)
	}
	return
}

func (q *query) matches(entry *entry) bool {
	return q.Question.Qtype == dns.TypeANY || q.Question.Qtype == entry.RR.Header().Rrtype
}

func equals(this, that *entry) bool {
	return dns.IsDuplicate(this.RR, that.RR)
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
		msg, addr, err := c.readMessage()
		if err != nil {
			// log dud packets
			log.Printf("Could not read from %v: %s", c.UDPConn, err)
			continue
		}
		if len(msg.Question) > 0 {
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
		for _, result := range c.query(msg.Question) {
			msg.Answer = append(msg.Answer, result.RR)
		}
		msg.Extra = append(msg.Extra, c.findExtra(msg.Answer...)...)
		if len(msg.Answer) > 0 {
			// nuke questions
			msg.Question = nil
			if err := c.writeMessage(msg.Msg, msg.UDPAddr); err != nil {
				log.Fatalf("Cannot send: %s", err)
			}
		}
	}
}

func (c *connector) query(qs []dns.Question) (results []*entry) {
	for _, q := range qs {
		results = append(results, c.Zone.query(q)...)
	}
	return
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
		res := c.Zone.query(q)
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
