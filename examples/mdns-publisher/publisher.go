package main

import (
	"log"

	"github.com/ugjka/mdns"
)

func mustPublish(zone *mdns.Zone, rr string) {
	if err := zone.Publish(rr); err != nil {
		log.Fatalf(`Unable to publish record "%s": %v`, rr, err)
	}
}

func main() {
	//In New we enable ipv4 and disable ipv6
	zone, err := mdns.New(true, false)
	if err != nil {
		log.Fatal(err)
	}
	// A simple example. Publish an A record for my router at 192.168.1.254.
	mustPublish(zone, "router.local. 60 IN A 192.168.1.254")
	mustPublish(zone, "254.1.168.192.in-addr.arpa. 60 IN PTR router.local.")

	// A more compilcated example. Publish a SVR record for ssh running on port
	// 22 for my home NAS.

	// Publish an A record as before
	mustPublish(zone, "stora.local. 60 IN A 192.168.1.200")
	mustPublish(zone, "200.1.168.192.in-addr.arpa. 60 IN PTR stora.local.")

	// Publish a PTR record for the _ssh._tcp DNS-SD type
	mustPublish(zone, "_ssh._tcp.local. 60 IN PTR stora._ssh._tcp.local.")

	// Publish a SRV record tying the _ssh._tcp record to an A record and a port.
	mustPublish(zone, "stora._ssh._tcp.local. 60 IN SRV 0 0 22 stora.local.")

	// Most mDNS browsing tools expect a TXT record for the service even if there
	// are not records defined by RFC 2782.
	mustPublish(zone, `stora._ssh._tcp.local. 60 IN TXT ""`)

	// Bind this service into the list of registered services for dns-sd.
	mustPublish(zone, "_services._dns-sd._udp.local. 60 IN PTR _ssh._tcp.local.")

	select {}
}
